#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM

make -C "$repo_root" install PREFIX=/usr DESTDIR="$stage" >/dev/null
installed=$stage/usr/bin/tm
if [[ ! -x "$installed" || "$(stat -c '%a' "$installed")" != 755 ||
      "$("$installed" --version)" != 'tm 0.1' ]]; then
    printf '%s\n' 'staged tm installation failed.' >&2
    exit 1
fi
