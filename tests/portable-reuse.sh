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
    rm -rf -- "$work"
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
git clone --quiet --local "$repo_root" "$work/producer"
git -C "$work/producer" config user.name 'tm acceptance test'
git -C "$work/producer" config user.email 'tm-acceptance@localhost'
mkdir -p "$work/producer/build"
cp "$probe" "$work/producer/build/portable-reuse-probe"
chmod 0755 "$work/producer/build/portable-reuse-probe"
printf '%s\n' 'unchanged-input' >"$work/producer/build/portable-input.txt"
mkdir -p "$work/producer/build/reports"

run_tm() {
    local checkout=$1 cache=$2
    local shared_store_for_run=${4:-}
    local run_id=${5:-$id}
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
            TM_RUNTIME_ROOT="$runtime_root" \
            "$tm_bin" --root . --profile "$profile" \
            --trust-policy "$trust_policy" "${key_option[@]}" \
            --output build/reports --explain -- \
            ./build/portable-reuse-probe build/portable-input.txt \
            build/reports/portable-reuse.txt "$run_id"
    )
}

if ! run_tm "$work/producer" "$work/cache-producer" "$signing_key" \
    >"$work/producer.out" 2>"$work/producer.err"; then
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
if grep -R -F "$work/producer" "$work/producer/.tm/results"; then
    printf '%s\n' 'Portable result metadata contains its producer checkout path.' >&2
    exit 1
fi
git -C "$work/producer" add -f .tm/results .tm/blobs \
    build/portable-input.txt build/portable-reuse-probe
git -C "$work/producer" commit --quiet -m 'Add portable reuse acceptance evidence'

git clone --quiet --local "$work/producer" "$work/consumer"
if [[ -e "$work/consumer/build/reports/portable-reuse.txt" ]]; then
    printf '%s\n' 'Consumer unexpectedly received the producer working-tree output.' >&2
    exit 1
fi
mkdir -p "$work/consumer/build/reports"
printf '%s\n' 'stale output' >"$work/consumer/build/reports/stale.txt"
if ! run_tm "$work/consumer" "$work/cache-consumer" \
    >"$work/consumer.out" 2>"$work/consumer.err"; then
    cat "$work/consumer.err" >&2
    exit 1
fi
if [[ -s "$work/consumer.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/consumer.err" ||
   [[ "$(cat "$work/consumer/build/reports/portable-reuse.txt")" != "$id:unchanged-input" ||
      -e "$work/consumer/build/reports/stale.txt" ]]; then
    cat "$work/consumer.err" >&2
    printf '%s\n' 'Clean consumer checkout failed to reuse and restore the trusted result.' >&2
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
   [[ "$(cat "$work/worktree-consumer/build/reports/portable-reuse.txt")" != \
      "$id:unchanged-input" ||
      -e "$work/worktree-consumer/build/reports/stale.txt" ]]; then
    cat "$work/worktree.err" >&2
    printf '%s\n' 'Linked worktree did not reuse and restore the per-user result.' >&2
    exit 1
fi

shared_id=$id-shared
git clone --quiet --local "$repo_root" "$work/shared-producer"
git -C "$work/shared-producer" config user.name 'tm acceptance test'
git -C "$work/shared-producer" config user.email 'tm-acceptance@localhost'
mkdir -p "$work/shared-producer/build/reports"
cp "$probe" "$work/shared-producer/build/portable-reuse-probe"
chmod 0755 "$work/shared-producer/build/portable-reuse-probe"
printf '%s\n' 'unchanged-input' \
    >"$work/shared-producer/build/portable-input.txt"
if ! run_tm "$work/shared-producer" "$work/cache-shared-producer" \
    "$signing_key" "$shared_store" "$shared_id" \
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
if grep -R -F "$work/shared-producer" "$work/shared-producer/.tm/results"; then
    printf '%s\n' 'Shared-store result metadata contains its producer checkout path.' >&2
    exit 1
fi
git -C "$work/shared-producer" add -f \
    build/portable-input.txt build/portable-reuse-probe
git -C "$work/shared-producer" commit --quiet -m \
    'Add shared-store acceptance fixture'
git clone --quiet --local "$work/shared-producer" "$work/shared-consumer"
git -C "$work/shared-consumer" rm --quiet --ignore-unmatch -r \
    .tm/results .tm/blobs
mkdir -p "$work/shared-consumer/build/reports"
printf '%s\n' 'stale output' \
    >"$work/shared-consumer/build/reports/stale.txt"
if ! run_tm "$work/shared-consumer" "$work/cache-shared-consumer" \
    '' "$shared_store" "$shared_id" >"$work/shared-consumer.out" \
    2>"$work/shared-consumer.err"; then
    cat "$work/shared-consumer.err" >&2
    exit 1
fi
if [[ -s "$work/shared-consumer.out" ]] ||
   ! grep -q '^tm: SKIP: trusted result ' "$work/shared-consumer.err" ||
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

concurrent_id=$id-concurrent
git clone --quiet --local "$repo_root" "$work/concurrent"
git -C "$work/concurrent" config user.name 'tm acceptance test'
git -C "$work/concurrent" config user.email 'tm-acceptance@localhost'
mkdir -p "$work/concurrent/build/reports"
cp "$probe" "$work/concurrent/build/portable-reuse-probe"
chmod 0755 "$work/concurrent/build/portable-reuse-probe"
printf '%s\n' 'unchanged-input' >"$work/concurrent/build/portable-input.txt"
run_tm "$work/concurrent" "$work/cache-concurrent-a" \
    "$signing_key" "$shared_store" "$concurrent_id" \
    >"$work/concurrent-a.out" 2>"$work/concurrent-a.err" &
concurrent_a=$!
run_tm "$work/concurrent" "$work/cache-concurrent-b" \
    "$signing_key" "$shared_store" "$concurrent_id" \
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
if [[ "$run_count" -ne 1 || "$skip_count" -ne 1 ||
      "$(cat "$work/concurrent/build/reports/portable-reuse.txt")" != \
      "$concurrent_id:unchanged-input" ]]; then
    cat "$work/concurrent-a.err" "$work/concurrent-b.err" >&2
    printf '%s\n' 'Shared-store cold-miss coordination did not execute exactly once.' >&2
    exit 1
fi

printf '%s\n' 'Checked-in/linked-worktree/shared-store reuse, state reversion, output restoration, invalidation, and cold-miss coordination passed.'
