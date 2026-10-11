#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BASE HEAD\n' "${0##*/}" >&2
    exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
classification=$(bash "$script_dir/tm-ci-classify-changes.sh" "$1" "$2")
tests_required=$(sed -n 's/^tests_required=//p' <<<"$classification")
has_results=$(sed -n 's/^has_results=//p' <<<"$classification")
results_only=$(sed -n 's/^results_only=//p' <<<"$classification")

for value in "$tests_required" "$has_results" "$results_only"; do
    if [[ "$value" != true && "$value" != false ]]; then
        printf '%s\n' 'CI classifier returned incomplete or invalid output.' >&2
        exit 2
    fi
done
if [[ "$results_only" == true && "$has_results" != true ]]; then
    printf '%s\n' 'CI classifier marked results-only without changed evidence.' >&2
    exit 2
fi
if [[ "$results_only" == true && "$tests_required" != false ]]; then
    printf '%s\n' 'CI classifier marked a test-relevant diff as results-only.' >&2
    exit 2
fi

if [[ "$results_only" == true && "$has_results" == true ]]; then
    echo 'Result-only change; validating trusted evidence without running tests.'
elif [[ "$tests_required" == true ]]; then
    make -C "$repo_root" clean test
    make -C "$repo_root" analyze
else
    echo 'Documentation or unrelated change; skipping source tests and analysis.'
fi

if [[ "$has_results" == true ]]; then
    (cd "$repo_root" && bash "$script_dir/tm-ci-validate-results.sh")
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s\n' \
        "tests_required=$tests_required" \
        "has_results=$has_results" \
        "results_only=$results_only" >>"$GITHUB_OUTPUT"
fi
