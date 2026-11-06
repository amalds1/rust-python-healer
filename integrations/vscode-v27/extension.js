'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vscode = require('vscode');
const { LspClient, MAX_SOURCE, MAX_DOCS } = require('./lsp_client');

let session = null;
let startup = null;
const signedApprovals = new Map();
const subscriptions = [];

function configuredClient() {
  const config = vscode.workspace.getConfiguration('rphReviewed');
  const python = config.get('pythonExecutable');
  const server = config.get('serverScript');
  const keyFile = config.get('reviewKeyFile');
  if (![python, server, keyFile].every(value => typeof value === 'string' &&
    path.isAbsolute(value))) {
    throw new Error('Set all three absolute rphReviewed paths in trusted machine settings.');
  }
  const actualServer = fs.realpathSync(server);
  if (path.basename(actualServer) !== 'developer_protocols_v21.py' ||
    path.basename(path.dirname(actualServer)) !== 'python') {
    throw new Error('serverScript must target the installed python/developer_protocols_v21.py.');
  }
  const key = fs.lstatSync(keyFile);
  if (!key.isFile() || key.nlink !== 1 || key.size < 16 || key.size > 128 ||
    (process.platform !== 'win32' && (key.mode & 0o077) !== 0)) {
    throw new Error('Review key must be a private regular 16–128-byte file.');
  }
  return new LspClient({ python, server: actualServer, keyFile });
}

function eligible(document) {
  return document.languageId === 'python' && document.uri.scheme === 'file' &&
    Buffer.byteLength(document.getText(), 'utf8') <= MAX_SOURCE;
}

async function ensureStarted() {
  if (session && session.ready) return session;
  if (startup) return startup;
  startup = (async () => {
    const candidate = configuredClient();
    await candidate.start();
    session = candidate;
    const docs = vscode.workspace.textDocuments.filter(eligible).slice(0, MAX_DOCS);
    for (const doc of docs) session.open(doc.uri.toString(), doc.version, doc.getText());
    return session;
  })();
  try { return await startup; }
  finally { startup = null; }
}

async function loadApproval() {
  const document = vscode.window.activeTextEditor?.document;
  if (!document || !eligible(document)) {
    vscode.window.showWarningMessage('Open a local Python file within the 32 KB analysis limit.');
    return;
  }
  try {
    const raw = await vscode.window.showInputBox({
      prompt: 'Paste reviewer-signed approval JSON (signed + signature); never paste a private key',
      ignoreFocusOut: true, password: false, validateInput: value => value.length > 8192 ? 'Approval exceeds 8 KB' : null
    });
    if (raw === undefined) return;
    if (raw.length > 8192) throw new Error('Approval exceeds 8 KB');
    const approval = JSON.parse(raw);
    if (!approval || Object.keys(approval).sort().join(',') !== 'signature,signed' ||
      typeof approval.signature !== 'string' || !approval.signed ||
      approval.signed.uri !== document.uri.toString() ||
      approval.signed.version !== document.version) {
      throw new Error('Approval must identify this document URI and current version.');
    }
    signedApprovals.set(document.uri.toString(), approval);
    vscode.window.showInformationMessage('Signed approval loaded. Use the Quick Fix lightbulb; signature is verified by the server.');
  } catch (error) { vscode.window.showErrorMessage(`Rust Python Healer: ${error.message}`); }
}

function convertAction(action, document) {
  if (action?.kind !== 'quickfix' || !action.edit ||
    !Array.isArray(action.edit.documentChanges) ||
    action.edit.documentChanges.length !== 1) throw new Error('Unsupported server edit shape');
  const change = action.edit.documentChanges[0];
  if (change.textDocument?.uri !== document.uri.toString() ||
    change.textDocument.version !== document.version ||
    !Array.isArray(change.edits) || change.edits.length !== 1) {
    throw new Error('Stale or non-local server edit');
  }
  const edit = change.edits[0];
  if (typeof edit.newText !== 'string' || edit.newText.length > 2000 || /[\r\n\0]/.test(edit.newText) ||
    !edit.range || !Number.isSafeInteger(edit.range.start?.line) ||
    !Number.isSafeInteger(edit.range.start?.character) ||
    !Number.isSafeInteger(edit.range.end?.line) ||
    !Number.isSafeInteger(edit.range.end?.character) ||
    edit.range.start.line < 0 || edit.range.start.character < 0 ||
    edit.range.end.line < 0 || edit.range.end.character < 0 ||
    edit.range.start.line !== edit.range.end.line ||
    edit.range.start.character > edit.range.end.character) throw new Error('Invalid edit range');
  const from = new vscode.Position(edit.range.start.line, edit.range.start.character);
  const to = new vscode.Position(edit.range.end.line, edit.range.end.character);
  const range = new vscode.Range(from, to);
  if (!document.validateRange(range).isEqual(range)) throw new Error('Edit range outside document');
  const result = new vscode.CodeAction(action.title, vscode.CodeActionKind.QuickFix);
  const edits = new vscode.WorkspaceEdit();
  edits.replace(document.uri, range, edit.newText);
  result.edit = edits;
  result.isPreferred = false;
  return result;
}

function activate(context) {
  subscriptions.push(vscode.commands.registerCommand('rphReviewed.loadApproval', loadApproval));
  subscriptions.push(vscode.commands.registerCommand('rphReviewed.restartServer', async () => {
    signedApprovals.clear();
    if (session) { await session.stop(); session = null; }
    try { await ensureStarted(); vscode.window.showInformationMessage('Offline LSP restarted.'); }
    catch (error) { vscode.window.showErrorMessage(`LSP restart failed: ${error.message}`); }
  }));
  subscriptions.push(vscode.workspace.onDidOpenTextDocument(doc => {
    if (session?.ready && eligible(doc) && !session.documents.has(doc.uri.toString())) {
      try { session.open(doc.uri.toString(), doc.version, doc.getText()); } catch (_) { /* quota */ }
    }
  }));
  subscriptions.push(vscode.workspace.onDidChangeTextDocument(event => {
    const uri = event.document.uri.toString();
    signedApprovals.delete(uri);
    if (session?.ready && session.documents.has(uri)) {
      try {
        if (eligible(event.document)) session.change(uri, event.document.version, event.document.getText());
        else session.close(uri);
      } catch (_) { session.close(uri); }
    }
  }));
  subscriptions.push(vscode.workspace.onDidCloseTextDocument(doc => {
    const uri = doc.uri.toString();
    signedApprovals.delete(uri);
    if (session?.ready) { try { session.close(uri); } catch (_) { /* shutdown */ } }
  }));
  subscriptions.push(vscode.languages.registerCodeActionsProvider({ language: 'python', scheme: 'file' }, {
    async provideCodeActions(document, range, context, token) {
      const uri = document.uri.toString();
      const approval = signedApprovals.get(uri);
      if (!approval || !eligible(document) || token.isCancellationRequested) return [];
      try {
        const client = await ensureStarted();
        if (!client.documents.has(uri)) client.open(uri, document.version, document.getText());
        if (client.documents.get(uri).version !== document.version) return [];
        const actions = await client.reviewedActions(uri, approval);
        if (token.isCancellationRequested || document.version !== approval.signed.version) return [];
        signedApprovals.delete(uri); // single use: reviewer must approve each attempt
        return actions.map(action => convertAction(action, document));
      } catch (error) {
        signedApprovals.delete(uri);
        vscode.window.showWarningMessage(`Reviewed fix rejected: ${error.message}`);
        return [];
      }
    }
  }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
  context.subscriptions.push(...subscriptions);
  // Autostart only with explicit trusted paths; no source or fix runs on activation.
  const config = vscode.workspace.getConfiguration('rphReviewed');
  if (config.get('pythonExecutable') && config.get('serverScript') && config.get('reviewKeyFile')) {
    ensureStarted().catch(error => vscode.window.showWarningMessage(`Offline LSP unavailable: ${error.message}`));
  }
}

async function deactivate() {
  signedApprovals.clear();
  if (session) { await session.stop(); session = null; }
}

module.exports = { activate, deactivate, convertAction, configuredClient };
