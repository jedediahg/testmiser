#!/usr/bin/env bash
set -euo pipefail

if [[ "${CI_PIPELINE_SOURCE:-}" == merge_request_event ]]; then
    echo 'Portable acceptance is deferred until reviewed code reaches a protected ref.'
    exit 0
fi

is_release_ref=false
if [[ -n "${CI_COMMIT_TAG:-}" ||
      "${CI_COMMIT_BRANCH:-}" == "${CI_DEFAULT_BRANCH:-}" ]]; then
    is_release_ref=true
fi

if [[ "$is_release_ref" == true &&
      "${CI_COMMIT_REF_PROTECTED:-false}" != true ]]; then
    echo 'The default branch and release tags must be protected refs.' >&2
    exit 1
fi

if [[ "${TM_CI_TESTS_REQUIRED:-}" != true ]]; then
    echo 'No source-test changes require portable acceptance.'
    exit 0
fi

if [[ "${CI_COMMIT_REF_PROTECTED:-false}" != true ]]; then
    echo 'Unprotected feature branch; portable acceptance is deferred.'
    exit 0
fi

if [[ "${TM_PORTABLE_ACCEPTANCE_PASSED:-}" != true ]]; then
    echo 'Portable acceptance did not complete for this protected source change.' >&2
    exit 1
fi

echo 'Protected source change passed portable acceptance.'
