# VS Code reviewed offline LSP client (v0.27)

This is a locally loadable VS Code extension folder with no runtime npm dependency.
Package with `npx @vscode/vsce package` where permitted, or use VS Code's
Extension Development Host to load the folder for local development. Neither
command is run by the repository's offline tests; actual VS Code behavior must
be independently verified inside the IDE.

Set the three **machine** settings to absolute, administrator-trusted paths:

- `rphReviewed.pythonExecutable`: interpreter 3.9–3.15 with stdlib.
- `rphReviewed.serverScript`: this installation's `python/developer_protocols_v21.py`.
- `rphReviewed.reviewKeyFile`: private 16–128 byte HMAC verification key, owner-only mode 0600 on Unix.

The Python process runs `--mode lsp --key-file ...` using `spawn` without a
shell. Only local Python documents up to 32 KB are mirrored via full-text
`didOpen`/`didChange`/`didClose` notifications. At most 12 documents are active.
The backend never evaluates source or saves files. To request a fix, run
**Rust Python Healer: Load Signed Reviewed Quickfix**, paste a separately
reviewed `{ "signed": ..., "signature": ... }` approval for the **current**
URI/version/hash, then select the Quick Fix lightbulb. The client never signs
approvals, never reads key bytes, and never automatically applies an edit.
The server verifies the HMAC, source SHA256, exact original span, and version.

The service's 128-frame budget is a deliberate safety limit. Restart the
client when exhausted. Avoid storing approval JSON or private keys in project
settings. An actual VS Code Extension Host test remains necessary for release.
