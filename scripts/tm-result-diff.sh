#!/usr/bin/env bash
set -euo pipefail

mode=${1:-}
base=${2:-}
head=${3:-}
if [[ "$mode" != only && "$mode" != any ]] || [[ -z "$base" || -z "$head" ]]; then
    exit 1
fi
if [[ "$base" =~ ^0+$ ]] || ! git cat-file -e "$base^{commit}" 2>/dev/null ||
   ! git cat-file -e "$head^{commit}" 2>/dev/null; then
    exit 1
fi

diff_file=$(mktemp)
trap 'rm -f "$diff_file"' EXIT
if ! git diff --no-renames --name-only -z "$base...$head" -- >"$diff_file"; then
    exit 1
fi
mapfile -d '' -t changed_files <"$diff_file"
if ((${#changed_files[@]} == 0)); then
    exit 1
fi

has_results=0
only_results=1
for path in "${changed_files[@]}"; do
    if [[ "$path" == .tm/results/* ]]; then
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
