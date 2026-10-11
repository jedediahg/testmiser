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

echo 'GitLab profile-change rules checks passed.'
