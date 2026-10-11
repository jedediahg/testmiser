#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
tm_bin=${TM_BIN:-$repo_root/build/tm}
profile=${TM_ACCEPTANCE_PROFILE:-}
trust_policy=${TM_ACCEPTANCE_TRUST_POLICY:-}
runtime_root=${TM_ACCEPTANCE_RUNTIME_ROOT:-}
signing_key=${TM_ACCEPTANCE_SIGNING_KEY:-}

for required in TM_ACCEPTANCE_PROFILE TM_ACCEPTANCE_TRUST_POLICY \
    TM_ACCEPTANCE_RUNTIME_ROOT TM_ACCEPTANCE_SIGNING_KEY; do
    if [[ -z "${!required:-}" ]]; then
        printf 'Set %s to run the portable reuse acceptance test.\n' "$required" >&2
        exit 2
    fi
done
for path in "$tm_bin" "$profile" "$trust_policy" "$runtime_root" "$signing_key"; do
    if [[ "$path" != /* || ! -e "$path" ]]; then
        printf 'Required acceptance path must exist and be absolute: %s\n' "$path" >&2
        exit 2
    fi
done
if [[ ! -x "$tm_bin" || ! -d "$runtime_root" || ! -f "$profile" ||
      ! -f "$trust_policy" || ! -f "$signing_key" ]]; then
    printf '%s\n' 'tm must be executable; profile, policy, key, and runtime must have the expected file types.' >&2
    exit 2
fi
probe=$repo_root/build/portable-reuse-probe
if [[ ! -x "$probe" ]]; then
    printf 'Build the portable acceptance probe first: make build/portable-reuse-probe\n' >&2
    exit 2
fi

work=$(mktemp -d)
shared_store_cleanup=
cleanup() {
    if [[ "${TM_ACCEPTANCE_KEEP_WORK:-}" == 1 ]]; then
        printf 'Keeping portable acceptance workspace: %s\n' "$work" >&2
    else
        rm -rf -- "$work"
    fi
    if [[ -n "$shared_store_cleanup" ]]; then
        rm -rf -- "$shared_store_cleanup"
    fi
}
trap cleanup EXIT HUP INT TERM
if [[ -n "${TM_ACCEPTANCE_SHARED_STORE:-}" ]]; then
    shared_store_root=$TM_ACCEPTANCE_SHARED_STORE
    if [[ "$shared_store_root" != /* || ! -d "$shared_store_root" ]]; then
        printf '%s\n' 'TM_ACCEPTANCE_SHARED_STORE must name an existing absolute directory.' >&2
        exit 2
    fi
    shared_store_cleanup=$(mktemp -d \
        "$shared_store_root/.tm-acceptance.XXXXXX")
    shared_store=$shared_store_cleanup
else
    shared_store=$work/shared-store
    mkdir -m 0700 "$shared_store"
fi
id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
git clone --quiet --no-hardlinks --local "$repo_root" "$work/producer"
git -C "$work/producer" config user.name 'tm acceptance test'
git -C "$work/producer" config user.email 'tm-acceptance@localhost'
mkdir -p "$work/producer/build"
cp "$probe" "$work/producer/build/portable-reuse-probe"
chmod 0755 "$work/producer/build/portable-reuse-probe"
printf '%s\n' 'unchanged-input' >"$work/producer/build/portable-input.txt"
printf '%s\n' 'declared-input-a' >"$work/producer/build/declared-only.txt"
mkdir -p "$work/producer/build/reports"

# Strict mode must fail before launching when the shared execution slot cannot
# be opened; it must not fall back to the per-user worktree lock.
mkdir -m 0700 -p "$work/cache-strict"
set +e
(
    cd "$work/producer"
    env -u TM_SHARED_STORE -u TM_FORCE \
        TM_COORDINATION_MODE=strict \
        TM_SHARED_STORE="$work/missing-strict-store" \
        XDG_CACHE_HOME="$work/cache-strict" \
        TM_RUNTIME_ROOT="$runtime_root" \
        "$tm_bin" --root . --profile "$profile" \
        --trust-policy "$trust_policy" --output build/reports --explain -- \
        ./build/portable-reuse-probe build/portable-input.txt \
        build/reports/strict-mode.txt "$id"
) >"$work/strict.out" 2>"$work/strict.err"
strict_status=$?
set -e
if [[ "$strict_status" -ne 125 || \
      -e "$work/producer/build/reports/strict-mode.txt" || \
      -s "$work/strict.out" ]] ||
   ! grep -q 'strict coordination unavailable; command was not launched' \
       "$work/strict.err"; then
    cat "$work/strict.err" >&2
    printf '%s\n' 'Strict coordination failed open or launched the command.' >&2
    exit 1
fi

run_tm() {
    local checkout=$1 cache=$2
    local shared_store_for_run=${4:-}
    local run_id=${5:-$id}
    local coordination_mode=${6:-available}
    local -a key_option=()
    local -a store_option=()
    mkdir -m 0700 -p "$cache"
    shift 2
    if [[ -n "${1:-}" ]]; then
        key_option=(--signing-key "$1")
        shift
    fi
    if [[ -n "$shared_store_for_run" ]]; then
        store_option=(TM_SHARED_STORE="$shared_store_for_run")
    fi
    (
        cd "$checkout"
        env -u TM_SHARED_STORE -u TM_FORCE -u TM_ACCEPTANCE_SIGNING_KEY \
            "${store_option[@]}" XDG_CACHE_HOME="$cache" \
            TM_COORDINATION_MODE="$coordination_mode" \
            TM_RUNTIME_ROOT="$runtime_root" \
            "$tm_bin" --root . --profile "$profile" \
            --trust-policy "$trust_policy" "${key_option[@]}" \
            --input build/declared-only.txt \
            --output build/reports --explain -- \
            ./build/portable-reuse-probe build/portable-input.txt \
            build/reports/portable-reuse.txt "$run_id"
    )
}

# Available mode must preserve normal test execution when the shared store is
# unreachable, while making the duplicate-work risk explicit.
fallback_id="$id-available-fallback"
if ! run_tm "$work/producer" "$work/cache-available-fallback" \
    '' "$work/missing-available-store" "$fallback_id" available \
    >"$work/available-fallback.out" 2>"$work/available-fallback.err"; then
    cat "$work/available-fallback.err" >&2
    printf '%s\n' 'Available coordination failed to run without the shared store.' >&2
    exit 1
fi
if [[ "$(cat "$work/available-fallback.out")" != "$fallback_id:unchanged-input" ||
      "$(cat "$work/producer/build/reports/portable-reuse.txt")" != "$fallback_id:unchanged-input" ]] ||
   ! grep -q 'shared-store invocation lock unavailable; concurrent cold runs may duplicate work' \
       "$work/available-fallback.err" ||
   ! grep -q '^tm: RUN:' "$work/available-fallback.err"; then
    cat "$work/available-fallback.err" >&2
    printf '%s\n' 'Available coordination did not warn and run with an unavailable shared store.' >&2
    exit 1
fi

assert_metadata_redacted() {
    local record_root=$1
    local record
    local -a records=()
    shift
    local value
    if [[ ! -d "$record_root" ]]; then
        printf 'Portable result records were not created: %s\n' \
            "$record_root" >&2
        return 1
    fi
    mapfile -d '' -t records < <(
        find "$record_root" -type f -name '*.tm.json' -print0
    )
    if ((${#records[@]} == 0)); then
        printf 'Portable result records were not found: %s\n' \
            "$record_root" >&2
        return 1
    fi
    for value in "$@"; do
        for record in "${records[@]}"; do
            if grep -F -q -- "$value" "$record"; then
                printf 'Portable result metadata contains host value: %s\n' \
                    "$value" >&2
                return 1
            fi
        done
    done
}

if ! (
    unset GITHUB_RUN_ID GITHUB_WORKSPACE GITHUB_TOKEN
    export CI_JOB_ID=gitlab-producer-job CI_PIPELINE_ID=gitlab-producer-pipeline
    export CI_PROJECT_DIR="$work/producer" CI_JOB_TOKEN=gitlab-test-token
    export HOME="$work/gitlab-host-home"
    run_tm "$work/producer" "$work/cache-producer" "$signing_key"
) >"$work/producer.out" 2>"$work/producer.err"; then
    cat "$work/producer.err" >&2
    printf '%s\n' 'Producer execution failed; inspect the profile/backend eligibility diagnostics above.' >&2
    exit 1
fi
if [[ "$(cat "$work/producer.out")" != "$id:unchanged-input" ||
      "$(cat "$work/producer/build/reports/portable-reuse.txt")" != "$id:unchanged-input" ]]; then
    printf '%s\n' 'Producer did not execute and create the expected output.' >&2
    exit 1
fi
grep -q '^tm: RUN:' "$work/producer.err"
if [[ ! -d "$work/producer/.tm/results" ]]; then
    cat "$work/producer.err" >&2
fi
assert_metadata_redacted "$work/producer/.tm/results" \
    "$work/producer" "$work/gitlab-host-home" \
    gitlab-producer-job gitlab-producer-pipeline gitlab-test-token

# A declared input participates even when the command never opens it.
printf '%s\n' 'declared-input-b' \
    >"$work/producer/build/declared-only.txt"
if ! run_tm "$work/producer" "$work/cache-producer" "$signing_key" \
    >"$work/declared-changed.out" 2>"$work/declared-changed.err"; then
    cat "$work/declared-changed.err" >&2
    exit 1
fi
if [[ "$(cat "$work/declared-changed.out")" != "$id:unchanged-input" ]] ||
   ! grep -q '^tm: RUN:' "$work/declared-changed.err" ||
   grep -q '^tm: SKIP: trusted result ' "$work/declared-changed.err"; then
    cat "$work/declared-changed.err" >&2
    printf '%s\n' 'Changed declared-only input reused stale evidence.' >&2
    exit 1
fi
printf '%s\n' 'declared-input-a' \
    >"$work/producer/build/declared-only.txt"
if ! run_tm "$work/producer" "$work/cache-producer" \
    >"$work/declared-restored.out" 2>"$work/declared-restored.err"; then
    cat "$work/declared-restored.err" >&2
    exit 1
fi
if [[ -s "$work/declared-restored.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/declared-restored.err"; then
    cat "$work/declared-restored.err" >&2
    printf '%s\n' 'Restoring a declared-only input did not recover its result.' >&2
    exit 1
fi

# A sign-enabled signal termination must never publish reusable success.
printf '%s\n' 'signal:terminated' \
    >"$work/producer/build/portable-input.txt"
signal_records_before=$(find "$work/producer/.tm/results" -type f \
    -name '*.tm.json' | wc -l)
for attempt in 1 2; do
    set +e
    run_tm "$work/producer" "$work/cache-signal" "$signing_key" \
        >"$work/signaled-$attempt.out" 2>"$work/signaled-$attempt.err"
    signaled_status=$?
    set -e
    if [[ "$signaled_status" -ne 143 || -s "$work/signaled-$attempt.out" ]] ||
       ! grep -q '^tm: RUN:' "$work/signaled-$attempt.err" ||
       grep -q '^tm: SKIP: trusted result ' "$work/signaled-$attempt.err"; then
        cat "$work/signaled-$attempt.err" >&2
        printf 'Signal-terminated run %s was reused or returned status %s.\n' \
            "$attempt" "$signaled_status" >&2
        exit 1
    fi
done
signal_records_after=$(find "$work/producer/.tm/results" -type f \
    -name '*.tm.json' | wc -l)
if [[ "$signal_records_after" -ne "$signal_records_before" ]]; then
    printf '%s\n' 'Signal-terminated command published a result sidecar.' >&2
    exit 1
fi
printf '%s\n' 'unchanged-input' \
    >"$work/producer/build/portable-input.txt"
if ! run_tm "$work/producer" "$work/cache-producer" "$signing_key" \
    >"$work/signal-recovery.out" 2>"$work/signal-recovery.err"; then
    cat "$work/signal-recovery.err" >&2
    exit 1
fi
if [[ -s "$work/signal-recovery.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/signal-recovery.err"; then
    cat "$work/signal-recovery.err" >&2
    printf '%s\n' 'Signal termination blocked the prior trusted success.' >&2
    exit 1
fi

git -C "$work/producer" add -f .tm/results .tm/blobs \
    build/portable-input.txt build/declared-only.txt \
    build/portable-reuse-probe
git -C "$work/producer" commit --quiet -m 'Add portable reuse acceptance evidence'

git clone --quiet --no-hardlinks --local "$work/producer" "$work/consumer"
if [[ -d "$work/consumer/.tm/blobs/sha256" ]]; then
    find "$work/consumer/.tm/blobs/sha256" -type f \
        -exec chmod 0444 -- {} +
fi
if [[ -e "$work/consumer/build/reports/portable-reuse.txt" ]]; then
    printf '%s\n' 'Consumer unexpectedly received the producer working-tree output.' >&2
    exit 1
fi
mkdir -p "$work/consumer/build/reports"
printf '%s\n' 'stale output' >"$work/consumer/build/reports/stale.txt"
if ! (
    unset CI_JOB_ID CI_PIPELINE_ID CI_PROJECT_DIR CI_JOB_TOKEN
    export GITHUB_RUN_ID=github-consumer-run
    export GITHUB_WORKSPACE="$work/consumer" GITHUB_TOKEN=github-test-token
    export HOME="$work/github-host-home"
    run_tm "$work/consumer" "$work/cache-consumer"
) >"$work/consumer.out" 2>"$work/consumer.err"; then
    cat "$work/consumer.err" >&2
    exit 1
fi
if [[ -s "$work/consumer.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/consumer.err" ||
   ! grep -Eq '^tm: SKIP: trusted result record=sha256:[0-9a-f]{64} verification=sha256:[0-9a-f]{64} source=repository$' \
       "$work/consumer.err" ||
   [[ "$(cat "$work/consumer/build/reports/portable-reuse.txt")" != "$id:unchanged-input" ||
      -e "$work/consumer/build/reports/stale.txt" ]]; then
    cat "$work/consumer.err" >&2
    printf '%s\n' 'Clean consumer checkout failed to reuse and restore the trusted result.' >&2
    exit 1
fi

# The executable itself is an approved input. A byte change must invalidate
# the hit even when the test data is unchanged; restoring it should recover A.
probe_copy=$work/portable-reuse.original
cp "$work/consumer/build/portable-reuse-probe" "$probe_copy"
probe_prefix_offset=$(LC_ALL=C grep -abo -m1 'fail:' \
    "$work/consumer/build/portable-reuse-probe" | cut -d: -f1)
if [[ ! "$probe_prefix_offset" =~ ^[0-9]+$ ]]; then
    printf '%s\n' 'Could not locate the portable probe mutation marker.' >&2
    exit 1
fi
printf 'FAIL:' | dd of="$work/consumer/build/portable-reuse-probe" \
    bs=1 seek="$probe_prefix_offset" conv=notrunc status=none
if ! run_tm "$work/consumer" "$work/cache-consumer" \
    >"$work/changed-test.out" 2>"$work/changed-test.err"; then
    cat "$work/changed-test.err" >&2
    exit 1
fi
if [[ "$(cat "$work/changed-test.out")" != "$id:unchanged-input" ]] ||
   ! grep -q '^tm: RUN:' "$work/changed-test.err" ||
   grep -q '^tm: SKIP: trusted result ' "$work/changed-test.err"; then
    cat "$work/changed-test.err" >&2
    printf '%s\n' 'Changed test executable reused stale evidence.' >&2
    exit 1
fi
cp "$probe_copy" "$work/consumer/build/portable-reuse-probe"
chmod 0755 "$work/consumer/build/portable-reuse-probe"
if ! run_tm "$work/consumer" "$work/cache-consumer" \
    >"$work/restored-test.out" 2>"$work/restored-test.err"; then
    cat "$work/restored-test.err" >&2
    exit 1
fi
if [[ -s "$work/restored-test.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/restored-test.err"; then
    cat "$work/restored-test.err" >&2
    printf '%s\n' 'Restoring the test executable did not recover trusted evidence.' >&2
    exit 1
fi

# A deterministic failure for state B must execute again on the next
# invocation, while the trusted success for state A remains reusable.
printf '%s\n' 'fail:broken-state' \
    >"$work/consumer/build/portable-input.txt"
for attempt in 1 2; do
    set +e
    run_tm "$work/consumer" "$work/cache-consumer" \
        >"$work/failed-$attempt.out" 2>"$work/failed-$attempt.err"
    failed_status=$?
    set -e
    if [[ "$failed_status" -ne 23 || -s "$work/failed-$attempt.out" ]] ||
       ! grep -q '^tm: RUN:' "$work/failed-$attempt.err" ||
       grep -q '^tm: SKIP: trusted result ' "$work/failed-$attempt.err"; then
        cat "$work/failed-$attempt.err" >&2
        printf 'Failed input state did not execute on attempt %s (status %s).\n' \
            "$attempt" "$failed_status" >&2
        exit 1
    fi
done
printf '%s\n' 'unchanged-input' \
    >"$work/consumer/build/portable-input.txt"
if ! run_tm "$work/consumer" "$work/cache-consumer" \
    >"$work/failure-recovery.out" 2>"$work/failure-recovery.err"; then
    cat "$work/failure-recovery.err" >&2
    exit 1
fi
if [[ -s "$work/failure-recovery.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/failure-recovery.err" ||
   [[ "$(cat "$work/consumer/build/reports/portable-reuse.txt")" != \
      "$id:unchanged-input" ]]; then
    cat "$work/failure-recovery.err" >&2
    printf '%s\n' 'A failed input state blocked an unrelated trusted success.' >&2
    exit 1
fi

printf '%s\n' 'changed-input' >"$work/consumer/build/portable-input.txt"
if ! run_tm "$work/consumer" "$work/cache-consumer" \
    >"$work/changed.out" 2>"$work/changed.err"; then
    cat "$work/changed.err" >&2
    exit 1
fi
if [[ "$(cat "$work/changed.out")" != "$id:changed-input" ||
      "$(cat "$work/consumer/build/reports/portable-reuse.txt")" != "$id:changed-input" ]] ||
   grep -q '^tm: SKIP: trusted result ' "$work/changed.err"; then
    cat "$work/changed.err" >&2
    printf '%s\n' 'Consumer reused evidence after an input changed.' >&2
    exit 1
fi
printf '%s\n' 'unchanged-input' >"$work/consumer/build/portable-input.txt"
if ! run_tm "$work/consumer" "$work/cache-consumer" \
    >"$work/restored.out" 2>"$work/restored.err"; then
    cat "$work/restored.err" >&2
    exit 1
fi
if [[ -s "$work/restored.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/restored.err" ||
   [[ "$(cat "$work/consumer/build/reports/portable-reuse.txt")" != \
      "$id:unchanged-input" ]]; then
    cat "$work/restored.err" >&2
    printf '%s\n' 'Returning to a previously verified input state did not reuse its result.' >&2
    exit 1
fi

git -C "$work/producer" worktree add --quiet --detach \
    "$work/worktree-consumer" HEAD
git -C "$work/worktree-consumer" rm --quiet -r .tm/results .tm/blobs
mkdir -p "$work/worktree-consumer/build/reports"
printf '%s\n' 'stale output' \
    >"$work/worktree-consumer/build/reports/stale.txt"
if ! run_tm "$work/worktree-consumer" "$work/cache-producer" \
    '' '' "$id" >"$work/worktree.out" 2>"$work/worktree.err"; then
    cat "$work/worktree.err" >&2
    printf '%s\n' 'Linked worktree failed to read the per-user result store.' >&2
    exit 1
fi
if [[ -s "$work/worktree.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/worktree.err" ||
   ! grep -Eq '^tm: SKIP: trusted result record=sha256:[0-9a-f]{64} verification=sha256:[0-9a-f]{64} source=per-user shared store$' \
       "$work/worktree.err" ||
   [[ "$(cat "$work/worktree-consumer/build/reports/portable-reuse.txt")" != \
      "$id:unchanged-input" ||
      -e "$work/worktree-consumer/build/reports/stale.txt" ]]; then
    cat "$work/worktree.err" >&2
    printf '%s\n' 'Linked worktree did not reuse and restore the per-user result.' >&2
    exit 1
fi

shared_id=$id-shared
git clone --quiet --no-hardlinks --local "$repo_root" "$work/shared-producer"
git -C "$work/shared-producer" config user.name 'tm acceptance test'
git -C "$work/shared-producer" config user.email 'tm-acceptance@localhost'
mkdir -p "$work/shared-producer/build/reports"
cp "$probe" "$work/shared-producer/build/portable-reuse-probe"
chmod 0755 "$work/shared-producer/build/portable-reuse-probe"
printf '%s\n' 'unchanged-input' \
    >"$work/shared-producer/build/portable-input.txt"
printf '%s\n' 'declared-input-a' \
    >"$work/shared-producer/build/declared-only.txt"
if ! (
    unset CI_JOB_ID CI_PIPELINE_ID CI_PROJECT_DIR CI_JOB_TOKEN
    export GITHUB_RUN_ID=github-producer-run
    export GITHUB_WORKSPACE="$work/shared-producer" \
        GITHUB_TOKEN=github-producer-token
    export HOME="$work/github-producer-host-home"
    run_tm "$work/shared-producer" "$work/cache-shared-producer" \
        "$signing_key" "$shared_store" "$shared_id"
) \
    >"$work/shared-producer.out" \
    2>"$work/shared-producer.err"; then
    cat "$work/shared-producer.err" >&2
    printf '%s\n' 'Shared-store producer execution failed.' >&2
    exit 1
fi
if [[ "$(cat "$work/shared-producer.out")" != \
      "$shared_id:unchanged-input" ||
      "$(cat "$work/shared-producer/build/reports/portable-reuse.txt")" != \
      "$shared_id:unchanged-input" ]]; then
    printf '%s\n' 'Shared-store producer did not create the expected output.' >&2
    exit 1
fi
if [[ ! -d "$work/shared-producer/.tm/results" ]]; then
    cat "$work/shared-producer.err" >&2
fi
assert_metadata_redacted "$work/shared-producer/.tm/results" \
    "$work/shared-producer" "$work/github-producer-host-home" \
    github-producer-run github-producer-token
git -C "$work/shared-producer" add -f \
    build/portable-input.txt build/declared-only.txt \
    build/portable-reuse-probe
git -C "$work/shared-producer" commit --quiet -m \
    'Add shared-store acceptance fixture'
git clone --quiet --no-hardlinks --local "$work/shared-producer" "$work/shared-consumer"
git -C "$work/shared-consumer" rm --quiet --ignore-unmatch -r \
    .tm/results .tm/blobs
mkdir -p "$work/shared-consumer/build/reports"
printf '%s\n' 'stale output' \
    >"$work/shared-consumer/build/reports/stale.txt"
if ! (
    unset GITHUB_RUN_ID GITHUB_WORKSPACE GITHUB_TOKEN
    export CI_JOB_ID=gitlab-consumer-job CI_PIPELINE_ID=gitlab-consumer-pipeline
    export CI_PROJECT_DIR="$work/shared-consumer" \
        CI_JOB_TOKEN=gitlab-consumer-token
    export HOME="$work/gitlab-consumer-host-home"
    run_tm "$work/shared-consumer" "$work/cache-shared-consumer" \
        '' "$shared_store" "$shared_id"
) >"$work/shared-consumer.out" \
    2>"$work/shared-consumer.err"; then
    cat "$work/shared-consumer.err" >&2
    exit 1
fi
if [[ -s "$work/shared-consumer.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/shared-consumer.err" ||
   ! grep -Eq '^tm: SKIP: trusted result record=sha256:[0-9a-f]{64} verification=sha256:[0-9a-f]{64} source=configured shared store$' \
       "$work/shared-consumer.err" ||
   [[ "$(cat "$work/shared-consumer/build/reports/portable-reuse.txt")" != \
      "$shared_id:unchanged-input" ||
      -e "$work/shared-consumer/build/reports/stale.txt" ]]; then
    cat "$work/shared-consumer.err" >&2
    printf '%s\n' 'Clean shared-store consumer failed to reuse and restore the result.' >&2
    exit 1
fi
printf '%s\n' 'changed-input' \
    >"$work/shared-consumer/build/portable-input.txt"
if ! run_tm "$work/shared-consumer" "$work/cache-shared-consumer" \
    '' "$shared_store" "$shared_id" >"$work/shared-changed.out" \
    2>"$work/shared-changed.err"; then
    cat "$work/shared-changed.err" >&2
    exit 1
fi
if [[ "$(cat "$work/shared-changed.out")" != \
      "$shared_id:changed-input" ||
      "$(cat "$work/shared-consumer/build/reports/portable-reuse.txt")" != \
      "$shared_id:changed-input" ]] ||
   grep -q '^tm: SKIP: trusted result ' "$work/shared-changed.err"; then
    cat "$work/shared-changed.err" >&2
    printf '%s\n' 'Shared store reused evidence after an input changed.' >&2
    exit 1
fi
rm -rf -- "$work/cache-shared-consumer"
mkdir -m 0700 "$work/cache-shared-consumer"
printf '%s\n' 'unchanged-input' \
    >"$work/shared-consumer/build/portable-input.txt"
if ! run_tm "$work/shared-consumer" "$work/cache-shared-consumer" \
    '' "$shared_store" "$shared_id" >"$work/shared-restored.out" \
    2>"$work/shared-restored.err"; then
    cat "$work/shared-restored.err" >&2
    exit 1
fi
if [[ -s "$work/shared-restored.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/shared-restored.err" ||
   [[ "$(cat "$work/shared-consumer/build/reports/portable-reuse.txt")" != \
      "$shared_id:unchanged-input" ]]; then
    cat "$work/shared-restored.err" >&2
    printf '%s\n' 'Shared store lost evidence for a previously verified input state.' >&2
    exit 1
fi

concurrent_id=wait-concurrent
git clone --quiet --no-hardlinks --local "$repo_root" "$work/concurrent"
git -C "$work/concurrent" config user.name 'tm acceptance test'
git -C "$work/concurrent" config user.email 'tm-acceptance@localhost'
mkdir -p "$work/concurrent/build/reports"
cp "$probe" "$work/concurrent/build/portable-reuse-probe"
chmod 0755 "$work/concurrent/build/portable-reuse-probe"
printf '%s\n' 'unchanged-input' >"$work/concurrent/build/portable-input.txt"
printf '%s\n' 'declared-input-a' \
    >"$work/concurrent/build/declared-only.txt"
run_tm "$work/concurrent" "$work/cache-concurrent-a" \
    "$signing_key" "$shared_store" "$concurrent_id" strict \
    >"$work/concurrent-a.out" 2>"$work/concurrent-a.err" &
concurrent_a=$!
for attempt in $(seq 1 200); do
    [[ -f "$work/concurrent/build/reports/portable-reuse.txt" ]] && break
    sleep 0.01
done
if [[ ! -f "$work/concurrent/build/reports/portable-reuse.txt" ]]; then
    printf '%s\n' 'Concurrent owner did not reach its output write.' >&2
    exit 1
fi
run_tm "$work/concurrent" "$work/cache-concurrent-b" \
    "$signing_key" "$shared_store" "$concurrent_id" strict \
    >"$work/concurrent-b.out" 2>"$work/concurrent-b.err" &
concurrent_b=$!
status_a=0
status_b=0
wait "$concurrent_a" || status_a=$?
wait "$concurrent_b" || status_b=$?
if [[ "$status_a" -ne 0 || "$status_b" -ne 0 ]]; then
    cat "$work/concurrent-a.err" "$work/concurrent-b.err" >&2
    printf 'Concurrent shared-store runs failed (exit %s, %s).\n' \
        "$status_a" "$status_b" >&2
    exit 1
fi
run_count=0
for output in "$work/concurrent-a.out" "$work/concurrent-b.out"; do
    if [[ -s "$output" ]]; then
        run_count=$((run_count + 1))
        if [[ "$(cat "$output")" != "$concurrent_id:unchanged-input" ]]; then
            printf '%s\n' 'Concurrent run produced unexpected output.' >&2
            exit 1
        fi
    fi
done
skip_count=$( (grep -h '^tm: SKIP: trusted result ' \
    "$work/concurrent-a.err" "$work/concurrent-b.err" || true) | wc -l)
wait_count=$( (grep -h '^tm: WAIT:' \
    "$work/concurrent-a.err" "$work/concurrent-b.err" || true) | wc -l)
if [[ "$run_count" -ne 1 || "$skip_count" -ne 1 ||
      "$wait_count" -ne 1 ||
      "$(cat "$work/concurrent/build/reports/portable-reuse.txt")" != \
      "$concurrent_id:unchanged-input" ]]; then
    cat "$work/concurrent-a.err" "$work/concurrent-b.err" >&2
    printf '%s\n' 'Shared-store cold-miss coordination did not execute exactly once.' >&2
    exit 1
fi

printf '%s\n' 'Checked-in/linked-worktree/shared-store reuse, test/input invalidation, failed/signal run recovery, state reversion, output restoration, and cold-miss coordination passed.'
