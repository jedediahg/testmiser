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

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
git clone --quiet --local "$repo_root" "$work/producer"
git -C "$work/producer" config user.name 'tm acceptance test'
git -C "$work/producer" config user.email 'tm-acceptance@localhost'

run_tm() {
    local checkout=$1 cache=$2
    local -a key_option=()
    shift 2
    if [[ -n "${1:-}" ]]; then
        key_option=(--signing-key "$1")
        shift
    fi
    (
        cd "$checkout"
        env -u TM_SHARED_STORE -u TM_FORCE -u TM_ACCEPTANCE_SIGNING_KEY \
            XDG_CACHE_HOME="$cache" TM_RUNTIME_ROOT="$runtime_root" \
            "$tm_bin" --root . --profile "$profile" \
            --trust-policy "$trust_policy" "${key_option[@]}" \
            --output build/reports --explain -- \
            /bin/sh -c 'mkdir -p build/reports; printf "%s\n" "$1" >build/reports/portable-reuse.txt; printf "%s\n" "$1"' \
            tm-acceptance "$id"
    )
}

if ! run_tm "$work/producer" "$work/cache-producer" "$signing_key" \
    >"$work/producer.out" 2>"$work/producer.err"; then
    cat "$work/producer.err" >&2
    printf '%s\n' 'Producer execution failed; inspect the profile/backend eligibility diagnostics above.' >&2
    exit 1
fi
if [[ "$(cat "$work/producer.out")" != "$id" ||
      "$(cat "$work/producer/build/reports/portable-reuse.txt")" != "$id" ]]; then
    printf '%s\n' 'Producer did not execute and create the expected output.' >&2
    exit 1
fi
grep -q '^tm: RUN:' "$work/producer.err"
if grep -R -F "$work/producer" "$work/producer/.tm/results"; then
    printf '%s\n' 'Portable result metadata contains its producer checkout path.' >&2
    exit 1
fi
git -C "$work/producer" add -f .tm/results .tm/blobs
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
   [[ "$(cat "$work/consumer/build/reports/portable-reuse.txt")" != "$id" ||
      -e "$work/consumer/build/reports/stale.txt" ]]; then
    cat "$work/consumer.err" >&2
    printf '%s\n' 'Clean consumer checkout failed to reuse and restore the trusted result.' >&2
    exit 1
fi

printf '%s\n' 'Portable cross-worktree reuse passed: committed evidence was trusted and restored without a producer key.'
