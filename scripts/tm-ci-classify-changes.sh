#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE HEAD\n' "${0##*/}" >&2
    exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
tests_required=false
has_results=false
results_only=false

if bash "$repo_root/scripts/tm-ci-has-test-changes.sh" "$1" "$2"; then
    tests_required=true
else
    status=$?
    if [[ $status -ne 1 ]]; then
        printf 'Could not classify test changes (status %s).\n' "$status" >&2
        exit "$status"
    fi
fi

if bash "$repo_root/scripts/tm-result-diff.sh" any "$1" "$2"; then
    has_results=true
    if bash "$repo_root/scripts/tm-result-diff.sh" only "$1" "$2"; then
        results_only=true
    else
        status=$?
        if [[ $status -ne 1 ]]; then
            printf 'Could not classify changed paths (status %s).\n' \
                "$status" >&2
            exit "$status"
        fi
    fi
else
    status=$?
    if [[ $status -ne 1 ]]; then
        printf 'Could not classify changed paths (status %s).\n' \
            "$status" >&2
        exit "$status"
    fi
fi

printf 'tests_required=%s\n' "$tests_required"
printf 'has_results=%s\n' "$has_results"
printf 'results_only=%s\n' "$results_only"
