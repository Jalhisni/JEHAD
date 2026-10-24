#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
mkdir -p "$HOME/.local/bin"
chmod +x JEHAD.py
ln -sfn "$(pwd)/JEHAD.py" "$HOME/.local/bin/jehad"
printf '\nJEHAD command installed at: %s\n' "$HOME/.local/bin/jehad"
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo 'Add this to ~/.zshrc or ~/.bashrc, then restart the terminal:'
  echo 'export PATH="$HOME/.local/bin:$PATH"'
fi
