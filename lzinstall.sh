#!/usr/bin/env bash

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
target="$HOME/.local/bin"
result="$target/pycon"

mkdir -p "$target" || exit 1

if [[ -e "$result" || -L "$result" ]]; then
  echo "Destination already exists: $result"
  	else
  	  ln -s -- "$here/python_pycon_source.py" "$result" || exit 1
  	  	echo "Installed pycon to $result"
fi

if [[ ":$PATH:" != *":$target:"* ]]; then
  path_line='export PATH="$HOME/.local/bin:$PATH"'

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  touch -- "$rc" || exit 1

if ! grep -Fxq -- "$path_line" "$rc"; then
  printf '\n%s\n' "$path_line" >> "$rc" || exit 1
fi
done
  echo "Open a new terminal to use pycon."
fi

