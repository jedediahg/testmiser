#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE HEAD\n' "${0##*/}" >&2
    exit 2
fi
if ! git cat-file -e "$2^{commit}" 2>/dev/null; then
    printf 'Cannot inspect CI diff: missing commit %s\n' "$2" >&2
    exit 2
fi
if [[ "$1" =~ ^0+$ ]]; then
    base=$(git hash-object -t tree -w --stdin </dev/null) || exit 2
    diff_args=("$base" "$2")
else
    if ! git cat-file -e "$1^{commit}" 2>/dev/null; then
        printf 'Cannot inspect CI diff: missing commit %s\n' "$1" >&2
        exit 2
    fi
    diff_args=("$1" "$2")
fi

if git diff --quiet "${diff_args[@]}" -- \
    .tm/profiles src include tests scripts docs/spec Makefile \
    .gitlab-ci.yml .github/workflows/ci.yml; then
    exit 1
else
    diff_status=$?
    if [[ $diff_status -eq 1 ]]; then
        exit 0
    fi
    printf 'Cannot inspect CI diff between %s and %s\n' "$1" "$2" >&2
    exit 2
fi
