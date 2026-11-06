# JetBrains PyCharm / IntelliJ LSP4IJ local integration (v0.27)

This directory is an **importable LSP4IJ user-defined language-server template**
for PyCharm/IntelliJ, not a signed native JetBrains plugin. LSP4IJ provides the
LSP client. No JetBrains runtime was started by the offline test suite.

1. Install a compatible trusted LSP4IJ plugin in the JetBrains IDE. In
   **Settings → Languages & Frameworks → Language Servers**, choose **Add**,
   then **Import from custom template...** and select this directory.
2. The template uses `$PROJECT_DIR$/integrations/pycharm-v27/start_lsp.py`.
   Open the Rust Python Healer repository as your project, or replace the
   command with an absolute path to your trusted installed launcher; adjust
   the Python executable if necessary.
3. In the LSP4IJ server definition's Environment Variables, set
   `RPH_LSP_KEY_FILE=/absolute/private/key` (Unix key must have owner-only
   permissions, e.g. 0600). Do not put the key or its contents in source files,
   VCS, or a directory writeable by untrusted code. The launcher validates
   key metadata and forwards stdio to the fixed Python LSP backend.
4. Map `Python` files with language ID `python`, and inspect LSP4IJ's console
   for initialize and full document sync. Leave other LSP servers enabled as
   needed; the Healer backend does not implement completion/hover/diagnostics.

**Important limit:** LSP4IJ's generic CodeAction request cannot provide the
project-specific `reviewedApproval` extension automatically. Therefore no
one-click quickfix is offered through this template. Signed quickfixes are
available in the companion VS Code extension, which supplies an explicitly
provided reviewer signature. Normal document synchronization and startup,
however, use genuine LSP4IJ configuration rather than mock editor calls.

The official template format is documented in
https://github.com/redhat-developer/lsp4ij/blob/main/docs/UserDefinedLanguageServerTemplate.md
and the custom import instructions in
https://github.com/redhat-developer/lsp4ij/blob/main/docs/UserDefinedLanguageServer.md .
