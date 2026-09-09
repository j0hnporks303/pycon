#!/usr/bin/env bash

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
target="$HOME/.local/bin"
result="$HOME/.local/bin/pycon"

mkdir -p "$target" || exit 1

if [[ -e "$result" || -L "$result" ]]; then
  echo "pycon is already installed"
  elif
  [[ -e "$target" || -L "$result" ]]; then
  ln -sf "$here"/python_pycon_source.py "$result"
fi

if [[ ":$PATH:" != *":$target:"* ]]; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi
