#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
workflow=$repo_root/.gitlab-ci.yml

if ! awk '
    /^verify:/ { in_verify = 1 }
    in_verify && /^[^[:space:]][^:]*:/ && $0 !~ /^verify:/ {
        in_verify = 0
    }
    in_verify && /TM_REQUIRE_PTRACE/ { requires_ptrace = 1 }
    END { exit requires_ptrace }
' "$workflow"; then
    printf '%s\n' 'Ordinary GitLab verification must not require ptrace from shared runners.' >&2
    exit 1
fi
if ! awk '
    /^portable-acceptance:/ { in_acceptance = 1 }
    in_acceptance && /^[^[:space:]][^:]*:/ &&
        $0 !~ /^portable-acceptance:/ { in_acceptance = 0 }
    in_acceptance && /TM_REQUIRE_PTRACE=1 bash -c/ { ptrace_runs++ }
    END { exit ptrace_runs != 2 }
' "$workflow"; then
    printf '%s\n' 'Both GitLab portable-acceptance execution paths must require ptrace.' >&2
    exit 1
fi

awk '
    /changes: &verify_changes/ { block = "verify"; next }
    /changes: &acceptance_changes/ { block = "acceptance"; next }
    /^[[:space:]]*- if:/ { block = "" }
    /\.tm\/profiles\/\*\*/ {
        if (block == "verify") verify = 1
        if (block == "acceptance") acceptance = 1
    }
    /docs\/spec\/\*\*/ {
        if (block == "verify") verify_spec = 1
        if (block == "acceptance") acceptance_spec = 1
    }
    END { if (!verify || !acceptance || !verify_spec || !acceptance_spec) exit 1 }
' "$workflow" || {
    printf '%s\n' 'GitLab change rules must run verification and portable acceptance for profile and specification changes.' >&2
    exit 1
}

grep -Fq 'CI_COMMIT_REF_PROTECTED == "true"' "$workflow" || {
    printf '%s\n' 'GitLab privileged acceptance must require a protected ref.' >&2
    exit 1
}
if ! awk '
    /^portable-acceptance:/ { in_acceptance = 1 }
    in_acceptance && /^[^[:space:]][^:]*:/ && $0 !~ /^portable-acceptance:/ {
        in_acceptance = 0
    }
    in_acceptance && /CI_PIPELINE_SOURCE != "merge_request_event"/ { excluded = 1 }
    END { exit !excluded }
' "$workflow"; then
    printf '%s\n' 'GitLab privileged acceptance must explicitly exclude merge-request pipelines.' >&2
    exit 1
fi

grep -Fq 'stage: acceptance-policy' "$workflow" || {
    printf '%s\n' 'GitLab must run a downstream acceptance policy check.' >&2
    exit 1
}
if ! awk '
    /^portable-acceptance-policy:/ { in_policy = 1 }
    in_policy && /^[^[:space:]][^:]*:/ && $0 !~ /^portable-acceptance-policy:/ {
        in_policy = 0
    }
    in_policy && /changes: \*acceptance_changes/ { source_changes = 1 }
    in_policy && /CI_PIPELINE_SOURCE != "merge_request_event"/ { excludes_mr = 1 }
    END { exit !(source_changes && excludes_mr) }
' "$workflow"; then
    printf '%s\n' 'GitLab acceptance classification must run only for non-MR source changes.' >&2
    exit 1
fi
if ! awk '
    /^protected-ref-policy:/ { in_policy = 1 }
    in_policy && /^[^[:space:]][^:]*:/ && $0 !~ /^protected-ref-policy:/ {
        in_policy = 0
    }
    in_policy && /GIT_STRATEGY: none/ { no_checkout = 1 }
    in_policy && /image: busybox:/ { lightweight_image = 1 }
    in_policy && /needs: \[\]/ { starts_immediately = 1 }
    in_policy && /CI_COMMIT_REF_PROTECTED/ { checks_protection = 1 }
    END {
        exit !(no_checkout && lightweight_image && starts_immediately &&
               checks_protection)
    }
' "$workflow"; then
    printf '%s\n' 'Protected-ref policy must start immediately without checkout or Git setup.' >&2
    exit 1
fi
grep -Fq 'dotenv: portable-acceptance.env' "$workflow" || {
    printf '%s\n' 'GitLab acceptance must publish a dotenv result for policy validation.' >&2
    exit 1
}

policy=$repo_root/scripts/tm-gitlab-acceptance-policy.sh
if CI_PIPELINE_SOURCE=push CI_COMMIT_BRANCH=main CI_COMMIT_TAG= \
    CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=false \
    TM_CI_TESTS_REQUIRED=true TM_PORTABLE_ACCEPTANCE_PASSED= \
    bash "$policy" >/dev/null 2>&1; then
    printf '%s\n' 'Unprotected default-branch source change unexpectedly qualified.' >&2
    exit 1
fi
if CI_PIPELINE_SOURCE=push CI_COMMIT_BRANCH=main CI_COMMIT_TAG= \
    CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=true \
    TM_CI_TESTS_REQUIRED=true TM_PORTABLE_ACCEPTANCE_PASSED= \
    bash "$policy" >/dev/null 2>&1; then
    printf '%s\n' 'Protected source change without acceptance unexpectedly qualified.' >&2
    exit 1
fi
CI_PIPELINE_SOURCE=push CI_COMMIT_BRANCH=main CI_COMMIT_TAG= \
    CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=true \
    TM_CI_TESTS_REQUIRED=true TM_PORTABLE_ACCEPTANCE_PASSED=true \
    bash "$policy" >/dev/null
CI_PIPELINE_SOURCE=merge_request_event CI_COMMIT_BRANCH= \
    CI_COMMIT_TAG= CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=false \
    TM_CI_TESTS_REQUIRED=true TM_PORTABLE_ACCEPTANCE_PASSED= \
    bash "$policy" >/dev/null
CI_PIPELINE_SOURCE=push CI_COMMIT_BRANCH=feature CI_COMMIT_TAG= \
    CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=false \
    TM_CI_TESTS_REQUIRED=true TM_PORTABLE_ACCEPTANCE_PASSED= \
    bash "$policy" >/dev/null
if CI_PIPELINE_SOURCE=push CI_COMMIT_BRANCH=main CI_COMMIT_TAG= \
    CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=false \
    TM_CI_TESTS_REQUIRED=false TM_PORTABLE_ACCEPTANCE_PASSED= \
    bash "$policy" >/dev/null 2>&1; then
    printf '%s\n' 'Unprotected docs-only default branch unexpectedly passed policy.' >&2
    exit 1
fi
CI_PIPELINE_SOURCE=push CI_COMMIT_BRANCH=main CI_COMMIT_TAG= \
    CI_DEFAULT_BRANCH=main CI_COMMIT_REF_PROTECTED=true \
    TM_CI_TESTS_REQUIRED=false TM_PORTABLE_ACCEPTANCE_PASSED= \
    bash "$policy" >/dev/null

echo 'GitLab acceptance and protected-runner policy checks passed.'
