#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
workflow=$repo_root/.github/workflows/ci.yml
runbook=$repo_root/docs/CI-INTEGRATION.md

grep -Fq "github.event_name != 'pull_request'" "$workflow"
grep -Fq \
    'github.event.pull_request.head.repo.full_name == github.repository' \
    "$workflow"
grep -Fq 'tm-portable-acceptance' "$runbook"
grep -Fq 'one-job ephemeral runner' "$runbook"
grep -Fq 'destroy or reimage its VM' "$runbook"

echo 'GitHub privileged-runner policy checks passed.'
