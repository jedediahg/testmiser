#!/usr/bin/env bash
set -euo pipefail

probe=${PORTABLE_REUSE_PROBE:-./build/portable-reuse-probe}
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
printf 'input\n' >"$work/input.txt"

set +e
env CI_JOB_ID=job GITHUB_TOKEN=token "$probe" \
    "$work/input.txt" "$work/tainted-output.txt" result
status=$?
set -e
if [[ "$status" -ne 3 || -e "$work/tainted-output.txt" ]]; then
    printf '%s\n' 'Portable fixture accepted supervisor/CI variables.' >&2
    exit 1
fi

"$probe" "$work/input.txt" "$work/clean-output.txt" result \
    >"$work/stdout.txt"
if [[ "$(cat "$work/stdout.txt")" != 'result:input' || \
      "$(cat "$work/clean-output.txt")" != 'result:input' ]]; then
    printf '%s\n' 'Portable fixture failed with a clean environment.' >&2
    exit 1
fi
