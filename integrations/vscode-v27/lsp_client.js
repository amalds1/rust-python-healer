'use strict';

// No dependency on a network service or on vscode-languageclient. The Python
// backend implements only this bounded LSP subset, so requests stay explicit.
const { spawn } = require('node:child_process');
const { TextDecoder } = require('node:util');

const MAX_MESSAGE = 100_000;
const MAX_SOURCE = 32_000;
const MAX_DOCS = 12;
const MAX_REQUESTS = 128;
const DEFAULT_TIMEOUT_MS = 4000;
const encoder = new TextDecoder('utf-8', { fatal: true });

function encodeFrame(message) {
  const data = Buffer.from(JSON.stringify(message), 'utf8');
  if (data.length < 1 || data.length > MAX_MESSAGE) throw new Error('lsp_frame_size');
  return Buffer.concat([Buffer.from(`Content-Length: ${data.length}\r\n\r\n`, 'ascii'), data]);
}

class FrameReader {
  constructor(onFrame, onError) {
    this.onFrame = onFrame;
    this.onError = onError;
    this.buffer = Buffer.alloc(0);
    this.expected = null;
    this.failed = false;
  }

  feed(chunk) {
    if (this.failed) return;
    try {
      if (!Buffer.isBuffer(chunk)) throw new Error('lsp_non_buffer');
      this.buffer = Buffer.concat([this.buffer, chunk]);
      while (true) {
        if (this.expected === null) {
          const boundary = this.buffer.indexOf('\r\n\r\n');
          if (boundary < 0) {
            if (this.buffer.length > 2048) throw new Error('lsp_header_quota');
            return;
          }
          const header = this.buffer.subarray(0, boundary).toString('ascii');
          const lines = header.split('\r\n');
          if (lines.length > 8 || lines.some(line => line.length > 254)) throw new Error('lsp_header_quota');
          const seen = new Set();
          for (const line of lines) {
            const split = line.indexOf(':');
            if (split < 1 || !/^[a-z-]+$/i.test(line.slice(0, split))) throw new Error('lsp_header_invalid');
            const key = line.slice(0, split).toLowerCase();
            const value = line.slice(split + 1).trim();
            if (seen.has(key) || !['content-length', 'content-type'].includes(key)) {
              throw new Error('lsp_header_duplicate_or_unsupported');
            }
            seen.add(key);
            if (key === 'content-length') {
              if (!/^[0-9]{1,7}$/.test(value)) throw new Error('lsp_length_invalid');
              this.expected = Number(value);
              if (this.expected < 1 || this.expected > MAX_MESSAGE) throw new Error('lsp_frame_size');
            } else if (!['application/vscode-jsonrpc', 'application/vscode-jsonrpc;charset=utf-8']
              .includes(value.toLowerCase().replaceAll(' ', ''))) {
              throw new Error('lsp_content_type_invalid');
            }
          }
          if (this.expected === null) throw new Error('lsp_length_missing');
          this.buffer = this.buffer.subarray(boundary + 4);
        }
        if (this.buffer.length < this.expected) return;
        const payload = this.buffer.subarray(0, this.expected);
        this.buffer = this.buffer.subarray(this.expected);
        this.expected = null;
        const decoded = encoder.decode(payload);
        const message = JSON.parse(decoded);
        if (message === null || typeof message !== 'object' || Array.isArray(message) ||
          message.jsonrpc !== '2.0') throw new Error('lsp_jsonrpc_invalid');
        this.onFrame(message);
      }
    } catch (error) {
      this.failed = true;
      this.onError(error);
    }
  }

  ended() {
    if (!this.failed && (this.buffer.length || this.expected !== null)) {
      this.failed = true;
      this.onError(new Error('lsp_truncated_frame'));
    }
  }
}

class LspClient {
  constructor({ python, server, keyFile, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (![python, server, keyFile].every(v => typeof v === 'string' && v.length > 0)) {
      throw new Error('lsp_config_required');
    }
    this.python = python;
    this.server = server;
    this.keyFile = keyFile;
    this.timeoutMs = timeoutMs;
    this.child = null;
    this.pending = new Map();
    this.documents = new Map();
    this.nextId = 1;
    this.sent = 0;
    this.ready = false;
    this.closed = false;
    this.fault = null;
  }

  async start() {
    if (this.child || this.closed) throw new Error('lsp_started_or_closed');
    this.child = spawn(this.python, [this.server, '--mode', 'lsp', '--key-file', this.keyFile], {
      stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false
    });
    const reader = new FrameReader(message => this._receive(message), error => this._fault(error));
    this.child.stdout.on('data', data => reader.feed(data));
    this.child.stdout.on('end', () => reader.ended());
    // Intentionally never expose stderr: it might contain local paths.
    this.child.stderr.resume();
    this.child.on('error', error => this._fault(error));
    this.child.on('exit', () => this._fault(new Error('lsp_server_exited')));
    const response = await this.request('initialize', {
      processId: process.pid, rootUri: null,
      capabilities: { textDocument: { codeAction: { codeActionLiteralSupport: {
        codeActionKind: { valueSet: ['quickfix'] } } } } }
    });
    if (!response || !response.capabilities || response.capabilities.textDocumentSync !== 1 ||
      response.capabilities.codeActionProvider !== true) throw new Error('lsp_capabilities_invalid');
    this.notify('initialized', {});
    this.ready = true;
    return response;
  }

  _fault(error) {
    if (this.fault) return;
    this.fault = error;
    this.ready = false;
    this.documents.clear();
    for (const item of this.pending.values()) {
      clearTimeout(item.timeout);
      item.reject(error);
    }
    this.pending.clear();
  }

  _receive(message) {
    if (!Object.prototype.hasOwnProperty.call(message, 'id')) return;
    const id = message.id;
    if (typeof id !== 'number' || !this.pending.has(id)) return;
    const item = this.pending.get(id);
    this.pending.delete(id);
    clearTimeout(item.timeout);
    if (message.error) item.reject(new Error(`lsp_rejected:${String(message.error.message).slice(0, 100)}`));
    else item.resolve(message.result);
  }

  _send(message) {
    if (this.closed || this.fault || !this.child || !this.child.stdin.writable) {
      throw this.fault || new Error('lsp_not_connected');
    }
    if (++this.sent > MAX_REQUESTS - 2) throw new Error('lsp_request_quota');
    this.child.stdin.write(encodeFrame(message));
  }

  request(method, params) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('lsp_request_timeout'));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timeout });
      try { this._send({ jsonrpc: '2.0', id, method, params }); }
      catch (error) { clearTimeout(timeout); this.pending.delete(id); reject(error); }
    });
  }

  notify(method, params) { this._send({ jsonrpc: '2.0', method, params }); }

  open(uri, version, text) {
    this._validateDocument(uri, version, text);
    if (this.documents.size >= MAX_DOCS && !this.documents.has(uri)) throw new Error('lsp_document_quota');
    if (this.documents.has(uri)) throw new Error('lsp_document_already_open');
    this.notify('textDocument/didOpen', { textDocument: { uri, languageId: 'python', version, text } });
    this.documents.set(uri, { version, text });
  }

  change(uri, version, text) {
    this._validateDocument(uri, version, text);
    const old = this.documents.get(uri);
    if (!old || version <= old.version) throw new Error('lsp_stale_or_unopened_change');
    this.notify('textDocument/didChange', {
      textDocument: { uri, version }, contentChanges: [{ text }]
    });
    this.documents.set(uri, { version, text });
  }

  close(uri) {
    if (!this.documents.has(uri)) return;
    this.notify('textDocument/didClose', { textDocument: { uri } });
    this.documents.delete(uri);
  }

  async reviewedActions(uri, approval, context = { diagnostics: [] }) {
    if (!this.documents.has(uri)) throw new Error('lsp_unopened_document');
    if (!approval || typeof approval !== 'object' || Array.isArray(approval) ||
      !approval.signed || typeof approval.signature !== 'string') {
      throw new Error('lsp_explicit_reviewed_approval_required');
    }
    const actions = await this.request('textDocument/codeAction', {
      textDocument: { uri }, range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
      context, reviewedApproval: approval
    });
    if (!Array.isArray(actions) || actions.length > 1) throw new Error('lsp_actions_invalid');
    return actions;
  }

  _validateDocument(uri, version, text) {
    if (typeof uri !== 'string' || uri.length < 1 || uri.length > 4096 || uri.includes('\0') ||
      !Number.isSafeInteger(version) || typeof text !== 'string' ||
      Buffer.byteLength(text, 'utf8') > MAX_SOURCE) throw new Error('lsp_invalid_document');
  }

  async stop() {
    if (this.closed) return;
    if (!this.fault && this.child && this.ready) {
      try { await this.request('shutdown', {}); this.notify('exit', {}); }
      catch (_) { /* Best-effort shutdown; the server has a hard request budget. */ }
    }
    this.closed = true;
    this.ready = false;
    if (this.child) {
      this.child.stdin.end();
      const child = this.child;
      const killer = setTimeout(() => { if (child.exitCode === null) child.kill(); }, 1000);
      killer.unref();
    }
  }
}

module.exports = { MAX_MESSAGE, MAX_SOURCE, MAX_DOCS, encodeFrame, FrameReader, LspClient };
