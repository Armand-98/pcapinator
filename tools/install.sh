#!/bin/sh
# Link pcapinator onto PATH under both its full name and its short name.
#
# The links point at the venv's console scripts, whose shebangs are absolute,
# so they resolve wherever they are called from. Moving the repo breaks them;
# re-run this script after a move.
#
#   tools/install.sh                  # link into /opt/homebrew/bin
#   tools/install.sh ~/.local/bin     # or anywhere else on PATH
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-/opt/homebrew/bin}"

if [ ! -x "$ROOT/.venv/bin/pcapinator" ]; then
    echo "no venv yet. Build it first:" >&2
    echo "  cd $ROOT && python3 -m venv .venv && ./.venv/bin/pip install -e ." >&2
    exit 1
fi

if [ ! -d "$BIN" ]; then
    echo "$BIN does not exist" >&2
    exit 1
fi

case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "warning: $BIN is not on your PATH" >&2 ;;
esac

for name in pcapinator pcapi; do
    ln -sf "$ROOT/.venv/bin/$name" "$BIN/$name"
    echo "linked $BIN/$name"
done
