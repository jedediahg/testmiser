#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE HEAD\n' "${0##*/}" >&2
    exit 2
fi
for revision in "$1" "$2"; do
    if ! git cat-file -e "$revision^{commit}" 2>/dev/null; then
        printf 'Cannot inspect CI diff: missing commit %s\n' "$revision" >&2
        exit 2
    fi
done

if git diff --quiet "$1" "$2" -- \
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
