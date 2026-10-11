#!/usr/bin/env bash
set -euo pipefail

mode=${1:-}
base=${2:-}
head=${3:-}
if [[ "$mode" != only && "$mode" != any ]] || [[ -z "$base" || -z "$head" ]]; then
    exit 2
fi
if ! git cat-file -e "$head^{commit}" 2>/dev/null; then
    exit 2
fi

diff_file=$(mktemp)
trap 'rm -f "$diff_file"' EXIT
if [[ "$base" =~ ^0+$ ]]; then
    base=$(git hash-object -t tree -w --stdin </dev/null) || exit 2
    diff_args=("$base" "$head")
else
    if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
        exit 2
    fi
    diff_args=("$base...$head")
fi
if ! git diff --no-renames --name-only -z "${diff_args[@]}" -- >"$diff_file"; then
    exit 2
fi
mapfile -d '' -t changed_files <"$diff_file"
if ((${#changed_files[@]} == 0)); then
    exit 1
fi

has_results=0
only_results=1
for path in "${changed_files[@]}"; do
    if [[ "$path" == .tm/results/* || "$path" == .tm/blobs/* ]]; then
        has_results=1
    else
        only_results=0
    fi
done
if [[ "$mode" == any ]]; then
    ((has_results == 1))
else
    ((only_results == 1))
fi
