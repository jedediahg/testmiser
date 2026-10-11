#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
workflow=$repo_root/.github/workflows/ci.yml
runbook=$repo_root/docs/CI-INTEGRATION.md

grep -Fq "github.event_name == 'push'" "$workflow"
grep -Fq "needs.test.outputs.tests_required == 'true'" "$workflow"
grep -Fq 'runs-on: ubuntu-24.04' "$workflow"
grep -Fq 'debian:trixie-slim' "$workflow"
grep -Fq -- '--privileged' "$workflow"
grep -Fq 'persist-credentials: false' "$workflow"
! grep -Fq 'TM_PORTABLE_ACCEPTANCE_ENABLED' "$workflow"
grep -Fq 'portable-acceptance-policy:' "$workflow"
grep -Fq 'if: always()' "$workflow"
grep -Fq 'bash scripts/tm-github-acceptance-policy.sh' "$workflow"
grep -Fq 'fresh `ubuntu-24.04` hosted VM' "$runbook"
grep -Fq 'persist-credentials: false' "$runbook"
! grep -Fq 'TM_PORTABLE_ACCEPTANCE_ENABLED' "$runbook"
! grep -Fq 'tm-portable-acceptance' "$runbook"

if EVENT_NAME=push REF=refs/heads/main TESTS_REQUIRED=true \
    ACCEPTANCE_RESULT=skipped bash \
    "$repo_root/scripts/tm-github-acceptance-policy.sh" >/dev/null 2>&1; then
    echo 'Skipped portable acceptance unexpectedly passed the main-branch policy.' >&2
    exit 1
fi
EVENT_NAME=push REF=refs/heads/main TESTS_REQUIRED=true \
    ACCEPTANCE_RESULT=success bash \
    "$repo_root/scripts/tm-github-acceptance-policy.sh"
EVENT_NAME=pull_request REF=refs/pull/1/merge TESTS_REQUIRED=true \
    ACCEPTANCE_RESULT=skipped bash \
    "$repo_root/scripts/tm-github-acceptance-policy.sh"
EVENT_NAME=push REF=refs/heads/main TESTS_REQUIRED=false \
    ACCEPTANCE_RESULT=skipped bash \
    "$repo_root/scripts/tm-github-acceptance-policy.sh"

echo 'GitHub portable-acceptance policy checks passed.'
