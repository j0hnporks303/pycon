#!/usr/bin/env bash

here="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
target="/usr/local/bin"
runtime="/usr/local/lib/pycon"
result="$target/pycon"
marker="# pycon managed system installation v1"

# Check both destinations before removing anything.
if [[ -L "$result" ]]; then
    existing="$(readlink "$result")" || exit 1
    if [[ "$existing" != "$here/python_pycon_source.py" && "$existing" != "$here/.venv/bin/pycon" ]]; then
        echo "Destination points elsewhere; leaving it untouched: $result" >&2
        exit 1
    fi
elif [[ -e "$result" ]]; then
    if [[ ! -f "$result" || "$(sed -n '2p' "$result")" != "$marker" ]]; then
        echo "Destination is not a managed pycon installation: $result" >&2
        exit 1
    fi
fi
if [[ -e "$runtime" || -L "$runtime" ]]; then
    if [[ -L "$runtime" || ! -d "$runtime" || -L "$runtime/.pycon-install" || ! -f "$runtime/.pycon-install" ]] ||
       [[ "$(cat "$runtime/.pycon-install")" != "$marker" ]]; then
        echo "Runtime directory is not a managed pycon installation: $runtime" >&2
        exit 1
    fi
fi
if [[ ! -e "$result" && ! -L "$result" && ! -e "$runtime" ]]; then
    echo "pycon is not installed at $result"
    exit 0
fi

elevated=()
if [[ "$EUID" -ne 0 ]]; then
    elevated=(sudo)
fi
if [[ -e "$result" || -L "$result" ]]; then
    "${elevated[@]}" rm -- "$result" || exit 1
fi
if [[ -d "$runtime" ]]; then
    "${elevated[@]}" rm -rf -- "$runtime" || exit 1
fi
echo "Uninstalled pycon from $result and removed its system runtime."
echo "Project files and the checkout's .venv have been kept."
