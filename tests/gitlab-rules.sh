#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
workflow=$repo_root/.gitlab-ci.yml

awk '
    /changes: &verify_changes/ { block = "verify"; next }
    /changes: &acceptance_changes/ { block = "acceptance"; next }
    /^[[:space:]]*- if:/ { block = "" }
    /\.tm\/profiles\/\*\*/ {
        if (block == "verify") verify = 1
        if (block == "acceptance") acceptance = 1
    }
    END { if (!verify || !acceptance) exit 1 }
' "$workflow" || {
    printf '%s\n' 'GitLab change rules must run verification and portable acceptance for profile changes.' >&2
    exit 1
}

grep -Fq 'CI_COMMIT_REF_PROTECTED == "true"' "$workflow" || {
    printf '%s\n' 'GitLab privileged acceptance must require a protected ref.' >&2
    exit 1
}
if awk '
    /^portable-acceptance:/ { in_acceptance = 1 }
    in_acceptance && /CI_PIPELINE_SOURCE == "merge_request_event"/ { found = 1 }
    END { exit !found }
' "$workflow"; then
    printf '%s\n' 'GitLab privileged acceptance must not run on merge-request refs.' >&2
    exit 1
fi

echo 'GitLab profile-change and protected-runner rules checks passed.'
