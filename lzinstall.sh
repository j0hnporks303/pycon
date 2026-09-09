#!/usr/bin/env bash

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || exit 1
target="$HOME/.local/bin"
result="$target/pycon"
venv_python="$here/.venv/bin/python"
launcher="$here/.venv/bin/pycon"

# Only replace links created for this checkout; preserve unrelated installations.
if [[ -e "$result" || -L "$result" ]]; then
    if [[ ! -L "$result" ]]; then
        echo "Destination already exists; leaving it untouched: $result" >&2
        exit 1
    fi
    existing="$(readlink -- "$result")" || exit 1
    if [[ "$existing" != "$here/python_pycon_source.py" && "$existing" != "$launcher" ]]; then
        echo "Destination points elsewhere; leaving it untouched: $result" >&2
        exit 1
    fi
fi

if [[ ! -x "$venv_python" ]]; then
    python3 -m venv "$here/.venv" || {
        echo "Could not create .venv. Ensure Python 3 and its venv support are installed." >&2
        exit 1
    }
fi

"$venv_python" -m pip install -r "$here/requirements-secrets.txt" || exit 1

# The launcher selects this venv even when the user's shell has not activated it.
launcher_tmp="$(mktemp "$here/.venv/bin/.pycon.XXXXXX")" || exit 1
trap 'rm -f -- "$launcher_tmp"' EXIT
printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' \
    "$venv_python" "$here/python_pycon_source.py" > "$launcher_tmp" || exit 1
chmod +x "$launcher_tmp" || exit 1
mv -fT -- "$launcher_tmp" "$launcher" || exit 1

mkdir -p "$target" || exit 1
if [[ -L "$result" ]]; then
    ln -sfnT -- "$launcher" "$result" || exit 1
else
    ln -sT -- "$launcher" "$result" || exit 1
fi
echo "Installed pycon with detect-secrets to $result"

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
