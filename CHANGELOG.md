## v2.1.1 — Nmap XML compatibility patch
- Accept the standard `<!DOCTYPE nmaprun>` header emitted by `nmap -oX -`.
- Preserve rejection of arbitrary doctypes and XML entity definitions.
- Add tests reproducing the terminal scan parse failure.

# Changelog

## v2.1.0 — Terminal Edition
- Removed PyQt6 GUI dependency; added native interactive `JEHAD >` console.
- Added command-oriented module selection and persisted per-session options.
- Kept Nmap XML scanning, local connections, exposure guidance, local UFW reversible rules and HTML/JSON reporting.
- Preserved previous `-m / --module` scripted CLI interface.
- Configured UFW to use terminal-only `sudo -n` credentials, avoiding GUI prompts.
- Inserted tagged deny rules with explicit precedence and clear local-effect warnings.
- Included unit tests for CLI input, authorization prompts, XML parsing and mocked UFW.
