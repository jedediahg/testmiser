#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
workflow=$repo_root/.github/workflows/ci.yml
runbook=$repo_root/docs/CI-INTEGRATION.md

grep -Fq "github.event_name == 'push'" "$workflow"
grep -Fq "vars.TM_PORTABLE_ACCEPTANCE_ENABLED == 'true'" "$workflow"
grep -Fq 'group: tm-portable-acceptance' "$workflow"
grep -Fq 'labels: tm-portable-acceptance' "$workflow"
grep -Fq 'tm-portable-acceptance' "$runbook"
grep -Fq 'ci.yml@refs/heads/main' "$runbook"
grep -Fq 'gh variable set TM_PORTABLE_ACCEPTANCE_ENABLED' "$runbook"
grep -Fq 'job-level event condition is useful for' "$runbook"
grep -Fq 'one-job ephemeral runner' "$runbook"
grep -Fq 'destroy or reimage its VM' "$runbook"

echo 'GitHub privileged-runner policy checks passed.'
