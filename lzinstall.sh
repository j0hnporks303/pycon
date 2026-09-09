#!/usr/bin/env bash

target="$HOME/.local/bin"
result="$HOME/.local/bin/pycon"

if [[ ! "$target" == "$HOME/.local/bin" ]]; then
  mkdir -p "$target"; ln -sf "$PWD"/python_pycon_source.py "$result" \
  	export PATH="$HOME/.local/bin:$PATH" >> ~/.bashrc && export PATH="$HOME/.local/bin:$PATH" >> ~/.zshrc
  else
  	  ln -sf "$PWD"/python_pycon_source.py "$result"
fi
