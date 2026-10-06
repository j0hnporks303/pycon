#!/usr/bin/env bash

umask 022
here="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 1
target="/usr/local/bin"
runtime="/usr/local/lib/pycon"
result="$target/pycon"
venv_python="$runtime/venv/bin/python"
marker="# pycon managed system installation v1"

# Migrate this checkout's old links; never overwrite an unrelated command.
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

python3_path="$(command -v python3)" || exit 1
"$python3_path" -I -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "Python 3.10 or newer is required." >&2
    exit 1
}
elevated=()
if [[ "$EUID" -ne 0 ]]; then
    elevated=(sudo)
fi

work="$(mktemp -d)" || exit 1
installed_tmp=""
cleanup() {
    rm -rf -- "$work"
    if [[ -n "$installed_tmp" ]]; then
        "${elevated[@]}" rm -f -- "$installed_tmp"
    fi
}
trap cleanup EXIT
printf '%s\n' "$marker" > "$work/.pycon-install" || exit 1

"${elevated[@]}" install -d -o 0 -g 0 -m 755 "$target" "$runtime" || exit 1
"${elevated[@]}" install -o 0 -g 0 -m 644 "$work/.pycon-install" "$runtime/.pycon-install" || exit 1
if [[ ! -x "$venv_python" ]]; then
    "${elevated[@]}" "$python3_path" -I -m venv --copies "$runtime/venv" || {
        echo "Could not create the system virtual environment. Ensure Python venv support is installed." >&2
        exit 1
    }
fi
"${elevated[@]}" "$venv_python" -I -c 'import sys; sys.exit(sys.version_info < (3, 10))' || exit 1
"${elevated[@]}" "$venv_python" -I -m pip install -r "$here/requirements.txt" || exit 1
"${elevated[@]}" chown -R 0:0 "$runtime" || exit 1
"${elevated[@]}" chmod -R a+rX,go-w "$runtime" || exit 1

# Install the actual program, with an absolute interpreter and isolated imports.
{
    printf '#!%s -I\n%s\n' "$venv_python" "$marker"
    tail -n +2 "$here/python_pycon_source.py"
} > "$work/pycon" || exit 1
installed_tmp="$("${elevated[@]}" mktemp "$target/.pycon.XXXXXX")" || exit 1
"${elevated[@]}" install -o 0 -g 0 -m 755 "$work/pycon" "$installed_tmp" || exit 1
"${elevated[@]}" mv -f "$installed_tmp" "$result" || exit 1
installed_tmp=""
echo "Installed pycon as a regular file at $result"

# Remove an older user-local link only when it belongs to this checkout.
legacy="$HOME/.local/bin/pycon"
if [[ -L "$legacy" ]]; then
    existing="$(readlink "$legacy")" || exit 1
    if [[ "$existing" == "$here/python_pycon_source.py" || "$existing" == "$here/.venv/bin/pycon" ]]; then
        rm -- "$legacy" || exit 1
        echo "Removed old link at $legacy; open a new terminal or refresh your shell's command cache."
    fi
fi
if [[ ":$PATH:" != *":$target:"* ]] && [[ "$EUID" -ne 0 ]]; then
    # Expand PATH when the user's shell reads its startup file.
    # shellcheck disable=SC2016
    path_line='export PATH="/usr/local/bin:$PATH"'
    for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
        touch "$rc" || exit 1
        if ! grep -Fxq -- "$path_line" "$rc"; then
            printf '\n%s\n' "$path_line" >> "$rc" || exit 1
        fi
    done
    echo "Open a new terminal to use pycon."
fi
