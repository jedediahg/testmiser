#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
workflow=$repo_root/.github/workflows/ci.yml
runbook=$repo_root/docs/CI-INTEGRATION.md

grep -Fq "github.event_name == 'push'" "$workflow"
grep -Fq 'image: debian:trixie-slim' "$workflow"
grep -Fq -- '--cap-add=SYS_PTRACE' "$workflow"
grep -Fq 'options: --cap-add=SYS_PTRACE' "$workflow"
grep -Fq 'git config --global --add safe.directory "$GITHUB_WORKSPACE"' "$workflow"
grep -Fq 'Install Trixie test dependencies' "$workflow"
grep -Fq 'bash build-essential ca-certificates' "$workflow"
if ! awk '
    /Install Trixie test dependencies/ { install = NR }
    /uses: actions\/checkout@/ && !checkout { checkout = NR }
    END { exit !(install > 0 && checkout > install) }
' "$workflow"; then
    echo 'Trixie dependencies must be installed before checkout.' >&2
    exit 1
fi
if awk '
    /^  test:$/ { in_test = 1; next }
    /^  [a-zA-Z0-9_-]+:$/ { in_test = 0 }
    in_test && /--privileged/ { found = 1 }
    END { exit !found }
' "$workflow"; then
    echo 'The ordinary test job must not use privileged Docker.' >&2
    exit 1
fi
grep -Fq "vars.TM_PORTABLE_ACCEPTANCE_ENABLED == 'true'" "$workflow"
grep -Fq "needs.test.outputs.tests_required == 'true'" "$workflow"
grep -Fq 'group: tm-portable-acceptance' "$workflow"
grep -Fq 'labels: tm-portable-acceptance' "$workflow"
grep -Fq 'debian:trixie-slim' "$workflow"
grep -Fq -- '--privileged' "$workflow"
grep -Fq 'persist-credentials: false' "$workflow"
grep -Fq 'portable-acceptance-policy:' "$workflow"
grep -Fq 'if: always()' "$workflow"
grep -Fq 'bash scripts/tm-github-acceptance-policy.sh' "$workflow"
grep -Fq 'tm-portable-acceptance' "$runbook"
grep -Fq 'ci.yml@refs/heads/main' "$runbook"
grep -Fq 'gh variable set TM_PORTABLE_ACCEPTANCE_ENABLED' "$runbook"
grep -Fq 'job-level event condition only' "$runbook"
grep -Fq 'one-job ephemeral runner' "$runbook"
grep -Fq 'persist-credentials: false' "$runbook"
grep -Fq 'destroy or reimage its VM' "$runbook"

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
