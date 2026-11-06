'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const test = require('node:test');

const root = path.resolve(__dirname, '..', '..', '..');
const server = path.join(root, 'python', 'developer_protocols_v21.py');
const tmp = fs.mkdtempSync(path.join(root, '.rph-v27-extension-'));
const keyFile = path.join(tmp, 'private.key');
fs.writeFileSync(keyFile, '32-byte-test-private-verification-key', { mode: 0o600 });
fs.chmodSync(keyFile, 0o600);
test.after(() => fs.rmSync(tmp, { recursive: true, force: true }));

let config = {};
let registered = [];
class Position { constructor(line, character) { this.line = line; this.character = character; } }
class Range {
  constructor(start, end) { this.start = start; this.end = end; }
  isEqual(other) { return this.start.line === other.start.line && this.start.character === other.start.character &&
    this.end.line === other.end.line && this.end.character === other.end.character; }
}
class WorkspaceEdit {
  constructor() { this.edits = []; }
  replace(uri, range, value) { this.edits.push({ uri, range, value }); }
}
class CodeAction {
  constructor(title, kind) { this.title = title; this.kind = kind; }
}
const fakeVscode = {
  workspace: {
    getConfiguration() { return { get(name) { return config[name] || ''; } }; },
    textDocuments: [],
    onDidOpenTextDocument(fn) { registered.push(['open', fn]); return { dispose() {} }; },
    onDidChangeTextDocument(fn) { registered.push(['change', fn]); return { dispose() {} }; },
    onDidCloseTextDocument(fn) { registered.push(['close', fn]); return { dispose() {} }; }
  },
  commands: { registerCommand(name, fn) { registered.push([name, fn]); return { dispose() {} }; } },
  languages: { registerCodeActionsProvider(selector, provider) {
    registered.push(['provider', provider]); return { dispose() {} };
  } },
  window: {
    activeTextEditor: null, showWarningMessage() {}, showInformationMessage() {}, showErrorMessage() {}
  },
  Position, Range, WorkspaceEdit, CodeAction,
  CodeActionKind: { QuickFix: 'quickfix' }
};

const originalLoad = Module._load;
let extension;
try {
  Module._load = function (id, parent, isMain) {
    if (id === 'vscode') return fakeVscode;
    return originalLoad.apply(this, arguments);
  };
  extension = require('../extension');
} finally { Module._load = originalLoad; }

function document() {
  return {
    uri: { toString() { return 'file:///exam.py'; }, scheme: 'file' }, version: 4,
    validateRange(range) { return range; },
    languageId: 'python', getText() { return 'x = 1\n'; }
  };
}

function action() {
  return { title: 'Reviewed offline safe quickfix', kind: 'quickfix',
    edit: { documentChanges: [{
      textDocument: { uri: 'file:///exam.py', version: 4 },
      edits: [{
        range: { start: { line: 0, character: 0 }, end: { line: 0, character: 1 } },
        newText: 'y'
      }]
    }] } };
}

test('configuration fails closed if machine settings are missing or relative', () => {
  config = {};
  assert.throws(() => extension.configuredClient(), /absolute/);
  config = { pythonExecutable: 'python3', serverScript: server, reviewKeyFile: keyFile };
  assert.throws(() => extension.configuredClient(), /absolute/);
});

test('configuration enforces fixed installed Python backend filename', () => {
  config = { pythonExecutable: process.execPath, serverScript: __filename, reviewKeyFile: keyFile };
  assert.throws(() => extension.configuredClient(), /serverScript must target/);
});

test('configuration accepts local private verification key without reading its contents', () => {
  config = { pythonExecutable: process.execPath, serverScript: server, reviewKeyFile: keyFile };
  const client = extension.configuredClient();
  assert.equal(client.server, fs.realpathSync(server));
  assert.equal(client.keyFile, keyFile);
});

test('configuration rejects insecure verification key permissions', () => {
  if (process.platform === 'win32') return;
  config = { pythonExecutable: process.execPath, serverScript: server, reviewKeyFile: keyFile };
  fs.chmodSync(keyFile, 0o644);
  assert.throws(() => extension.configuredClient(), /private regular/);
  fs.chmodSync(keyFile, 0o600);
});

test('normal signed proposal becomes nonpreferred native user-selected quickfix', () => {
  const native = extension.convertAction(action(), document());
  assert.equal(native.kind, 'quickfix');
  assert.equal(native.isPreferred, false);
  assert.equal(native.edit.edits.length, 1);
  assert.equal(native.edit.edits[0].value, 'y');
});

test('stale URI/version and multi-document edit are rejected', () => {
  const stale = action();
  stale.edit.documentChanges[0].textDocument.version = 3;
  assert.throws(() => extension.convertAction(stale, document()), /Stale or non-local/);
  const wrongUri = action();
  wrongUri.edit.documentChanges[0].textDocument.uri = 'file:///someone_else.py';
  assert.throws(() => extension.convertAction(wrongUri, document()), /Stale or non-local/);
  const extra = action();
  extra.edit.documentChanges.push(extra.edit.documentChanges[0]);
  assert.throws(() => extension.convertAction(extra, document()), /Unsupported/);
});

test('multiline and out-of-range proposals are rejected by editor adapter', () => {
  const multiline = action();
  multiline.edit.documentChanges[0].edits[0].newText = 'x\nimport os';
  assert.throws(() => extension.convertAction(multiline, document()), /Invalid edit range/);
  const invalid = action();
  invalid.edit.documentChanges[0].edits[0].range.start.character = -1;
  assert.throws(() => extension.convertAction(invalid, document()), /Invalid edit range/);
  const outOfRange = action();
  const doc = document();
  doc.validateRange = range => new Range(range.start, new Position(0, 0));
  assert.throws(() => extension.convertAction(outOfRange, doc), /outside document/);
});

test('extension activates without configured subprocess or implicit quickfix', async () => {
  config = {};
  registered = [];
  const context = { subscriptions: [] };
  extension.activate(context);
  assert.equal(context.subscriptions.length, 6);
  const provider = registered.find(item => item[0] === 'provider')[1];
  const actions = await provider.provideCodeActions(document(), null, {}, { isCancellationRequested: false });
  assert.deepEqual(actions, []);
  await extension.deactivate();
});
