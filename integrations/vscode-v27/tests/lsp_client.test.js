'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { FrameReader, encodeFrame, LspClient, MAX_SOURCE, MAX_DOCS } = require('../lsp_client');

const root = path.resolve(__dirname, '..', '..', '..');
const server = path.join(root, 'python', 'developer_protocols_v21.py');
const python = process.env.RPH_PYTHON || 'python3';
const fixture = fs.mkdtempSync(path.join(root, '.rph-v27-client-'));
const privateRoot = process.platform === 'win32' ? path.join(fixture, 'private-fixture') : fixture;
const keyFile = path.join(privateRoot, 'private.key');
const key = Buffer.from('32-byte-test-review-key-v27-no-real-secret');
test.after(() => fs.rmSync(fixture, { recursive: true, force: true }));

function nativeFixtureKey(file, payload, newRoot) {
  const script = 'import importlib.util,pathlib,sys; s=importlib.util.spec_from_file_location("privacy_fixture",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.private_fixture_root(pathlib.Path(sys.argv[2]).parent.parent) if sys.argv[3]=="new-root" else None; m.write_new_private_fixture(pathlib.Path(sys.argv[2]),sys.stdin.buffer.read())';
  const result = require('node:child_process').spawnSync(python, ['-I', '-S', '-B', '-c', script, path.join(root, 'tests', 'windows_privacy_fixtures.py'), file, newRoot ? 'new-root' : 'new-leaf'], { input: payload, timeout: 8000 });
  assert.equal(result.status, 0, 'native_private_fixture_creation_failed');
}

if (process.platform === 'win32') nativeFixtureKey(keyFile, key, true);
else {
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  fs.chmodSync(keyFile, 0o600);
}
function fixtureAcl(file, publicRead) {
  const script = 'import importlib.util,sys; s=importlib.util.spec_from_file_location("privacy_fixture",sys.argv[1]); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); (m.set_public_read_acl if sys.argv[3]=="public" else m.set_private_acl)(sys.argv[2])';
  const result = require('node:child_process').spawnSync(python, ['-I', '-S', '-B', '-c', script, path.join(root, 'tests', 'windows_privacy_fixtures.py'), file, publicRead ? 'public' : 'private']);
  assert.equal(result.status, 0, result.stderr.toString());
}

async function client() {
  const c = new LspClient({ python, server, keyFile, timeoutMs: 3500 });
  await c.start();
  return c;
}

function signed(uri, version, text, overrides = {}) {
  const payload = {
    uri, version, sha256: crypto.createHash('sha256').update(text).digest('hex'),
    line: 0, start: 0, end: 1, old: 'x', replacement: 'y', reviewer: 'unit-test-reviewer',
    ...overrides
  };
  const sort = object => {
    if (Array.isArray(object)) return object.map(sort);
    if (object !== null && typeof object === 'object') {
      const result = {};
      for (const k of Object.keys(object).sort()) result[k] = sort(object[k]);
      return result;
    }
    return object;
  };
  const signature = crypto.createHmac('sha256', key).update(JSON.stringify(sort(payload))).digest('hex');
  return { signed: payload, signature };
}

function framedMessage(message, options = {}) {
  const data = Buffer.from(JSON.stringify(message));
  const prelude = options.contentType ?
    `Content-Type: application/vscode-jsonrpc; charset=utf-8\r\nContent-Length: ${data.length}\r\n\r\n` :
    `Content-Length: ${data.length}\r\n\r\n`;
  return Buffer.concat([Buffer.from(prelude), data]);
}

test('real frame encoder handles Unicode byte length', () => {
  const message = { jsonrpc: '2.0', id: 5, result: { symbol: '🚀' } };
  const frame = encodeFrame(message);
  const header = frame.subarray(0, frame.indexOf('\r\n\r\n')).toString();
  assert.equal(Number(header.split(': ')[1]), Buffer.byteLength(JSON.stringify(message)));
});

test('fragmented frames and optional content-type roundtrip', () => {
  const seen = [], errors = [];
  const reader = new FrameReader(message => seen.push(message), e => errors.push(e.message));
  const one = { jsonrpc: '2.0', id: 1, result: null };
  const two = { jsonrpc: '2.0', id: 2, result: 'é' };
  const all = Buffer.concat([framedMessage(one, { contentType: true }), framedMessage(two)]);
  for (let i = 0; i < all.length; i += 3) reader.feed(all.subarray(i, i + 3));
  assert.deepEqual(seen, [one, two]);
  assert.deepEqual(errors, []);
});

test('rejects duplicate frame lengths', () => {
  const errors = [];
  const reader = new FrameReader(() => assert.fail('not a frame'), e => errors.push(e.message));
  reader.feed(Buffer.from('Content-Length: 1\r\nContent-Length: 1\r\n\r\nx'));
  assert.deepEqual(errors, ['lsp_header_duplicate_or_unsupported']);
});

test('rejects Content-Type downgrade', () => {
  const errors = [];
  const reader = new FrameReader(() => assert.fail('not a frame'), e => errors.push(e.message));
  reader.feed(Buffer.from('Content-Length: 1\r\nContent-Type: application/xml\r\n\r\nx'));
  assert.deepEqual(errors, ['lsp_content_type_invalid']);
});

test('rejects oversized and missing frame lengths', () => {
  for (const header of ['Content-Length: 100001\r\n\r\n', 'Content-Type: application/vscode-jsonrpc\r\n\r\n']) {
    let error = null;
    new FrameReader(() => assert.fail('not a frame'), e => { error = e; }).feed(Buffer.from(header));
    assert.ok(error);
  }
});

test('rejects malformed UTF-8 and truncated frame', () => {
  let error = null;
  const reader = new FrameReader(() => assert.fail('not a frame'), e => { error = e; });
  reader.feed(Buffer.concat([Buffer.from('Content-Length: 2\r\n\r\n'), Buffer.from([0xc3, 0x28])]));
  assert.ok(error);
  let truncation = null;
  const half = new FrameReader(() => {}, e => { truncation = e; });
  half.feed(Buffer.from('Content-Length: 3\r\n\r\nx'));
  half.ended();
  assert.equal(truncation.message, 'lsp_truncated_frame');
});

test('client rejects invalid configuration and oversize source', () => {
  assert.throws(() => new LspClient({ python: '', server, keyFile }), /lsp_config_required/);
  const c = new LspClient({ python, server, keyFile });
  assert.throws(() => c.open('file:///a.py', 1, 'z'.repeat(MAX_SOURCE + 1)), /lsp_invalid_document/);
  assert.throws(() => c.change('file:///a.py', 1, 'x'), /lsp_stale_or_unopened_change/);
});

test('actual CPython backend initializes and stops with shutdown/exit', async () => {
  const c = await client();
  try {
    assert.equal(c.ready, true);
    assert.equal(c.sent, 2); // initialize + initialized
  } finally { await c.stop(); }
  assert.equal(c.closed, true);
  assert.equal(c.ready, false);
});

test('actual backend syncs didOpen, didChange and didClose, enforces versions', async () => {
  const c = await client();
  try {
    c.open('file:///sync.py', 3, 'x = 1\n');
    assert.throws(() => c.change('file:///sync.py', 3, 'x = 2\n'), /lsp_stale/);
    c.change('file:///sync.py', 4, 'x = 3\n');
    assert.deepEqual(c.documents.get('file:///sync.py'), { version: 4, text: 'x = 3\n' });
    c.close('file:///sync.py');
    assert.equal(c.documents.size, 0);
    await assert.rejects(c.reviewedActions('file:///sync.py', {}), /lsp_unopened_document/);
  } finally { await c.stop(); }
});

test('actual backend rejects unsigned or forged quickfix approvals', async () => {
  const c = await client();
  try {
    const uri = 'file:///untrusted.py', text = 'x = 1\n';
    c.open(uri, 2, text);
    await assert.rejects(c.reviewedActions(uri, null), /lsp_explicit_reviewed_approval_required/);
    const forged = signed(uri, 2, text);
    forged.signature = '0'.repeat(64);
    await assert.rejects(c.reviewedActions(uri, forged), /untrusted_edit_signature/);
  } finally { await c.stop(); }
});

test('actual backend returns reviewed proposal without applying file edit', async () => {
  const c = await client();
  const actualFile = path.join(fixture, 'reviewed.py');
  fs.writeFileSync(actualFile, 'x = 1\n');
  try {
    const uri = `file://${actualFile}`, text = 'x = 1\n';
    c.open(uri, 1, text);
    const actions = await c.reviewedActions(uri, signed(uri, 1, text));
    assert.equal(actions.length, 1);
    assert.equal(actions[0].edit.documentChanges[0].textDocument.version, 1);
    assert.deepEqual(actions[0].edit.documentChanges[0].edits[0].newText, 'y');
    assert.equal(fs.readFileSync(actualFile, 'utf8'), text);
    assert.equal(actions[0].data.applied, false);
  } finally { await c.stop(); }
});

test('actual backend rejects a stale approval after didChange', async () => {
  const c = await client();
  try {
    const uri = 'file:///stale.py', text = 'x = 1\n';
    c.open(uri, 1, text);
    c.change(uri, 2, 'x = 2\n');
    await assert.rejects(c.reviewedActions(uri, signed(uri, 1, text)), /stale_document_or_version/);
  } finally { await c.stop(); }
});

test('actual backend rejects signed mismatching original span', async () => {
  const c = await client();
  try {
    const uri = 'file:///old.py', text = 'x = 1\n';
    c.open(uri, 1, text);
    await assert.rejects(c.reviewedActions(uri, signed(uri, 1, text, { old: 'wrong' })), /original_span_not_equal/);
  } finally { await c.stop(); }
});

test('actual backend forbids editing a closed document', async () => {
  const c = await client();
  try {
    const uri = 'file:///closed.py', text = 'x = 1\n';
    c.open(uri, 1, text);
    c.close(uri);
    await assert.rejects(c.reviewedActions(uri, signed(uri, 1, text)), /lsp_unopened_document/);
  } finally { await c.stop(); }
});

test('actual backend enforces 12-document memory budget', async () => {
  const c = await client();
  try {
    for (let i = 0; i < MAX_DOCS; i++) c.open(`file:///quota${i}.py`, 1, 'x = 1\n');
    assert.throws(() => c.open('file:///quota12.py', 1, 'x = 1\n'), /lsp_document_quota/);
  } finally { await c.stop(); }
});

test('actual backend refuses world-readable verification key', async () => {
  const insecure = path.join(privateRoot, 'insecure.key');
  if (process.platform === 'win32') nativeFixtureKey(insecure, key, false);
  else fs.writeFileSync(insecure, key);
  fs.chmodSync(insecure, 0o644);
  if (process.platform === 'win32') fixtureAcl(insecure, true);
  const c = new LspClient({ python, server, keyFile: insecure, timeoutMs: 1500 });
  await assert.rejects(c.start(), /lsp_server_exited|lsp_truncated_frame|lsp_request_timeout/);
  await c.stop();
});
