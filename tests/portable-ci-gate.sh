#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
fake_bin=$work/bin
mkdir -p "$fake_bin"

cat >"$fake_bin/bwrap" <<'EOF'
#!/bin/sh
exit 1
EOF
cat >"$fake_bin/busybox" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$fake_bin/sudo" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$fake_bin/bwrap" "$fake_bin/busybox" "$fake_bin/sudo"

set +e
TM_ALLOW_BACKEND_UNAVAILABLE=1 PATH="$fake_bin:/usr/bin:/bin" \
    bash "$repo_root/tests/portable-reuse-ci.sh" \
    >"$work/gate.log" 2>&1
status=$?
set -e
if [[ "$status" -ne 1 ]] ||
   ! grep -q 'signed cross-worktree acceptance did not run' "$work/gate.log" ||
   grep -q '::warning::' "$work/gate.log"; then
    cat "$work/gate.log" >&2
    printf '%s\n' 'Portable CI gate did not fail closed when Bubblewrap was unavailable.' >&2
    exit 1
fi
