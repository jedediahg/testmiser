#!/usr/bin/env bash
set -euo pipefail

if [[ "${EVENT_NAME:-}" == push && "${REF:-}" == refs/heads/main &&
      "${TESTS_REQUIRED:-}" == true &&
      "${ACCEPTANCE_RESULT:-}" != success ]]; then
    echo '::error::Portable acceptance did not pass for this main-branch source change.'
    exit 1
fi
