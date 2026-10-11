#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
classify="$repo_root/scripts/tm-ci-classify-changes.sh"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
fixture=$work/repo
mkdir -p "$fixture"
git -C "$fixture" init --quiet
git -C "$fixture" config user.name 'tm CI classification test'
git -C "$fixture" config user.email 'tm-ci-classify@localhost'
mkdir -p "$fixture/src" "$fixture/docs" "$fixture/.tm/profiles"
printf 'int main(void) { return 0; }\n' >"$fixture/src/main.c"
printf 'guide\n' >"$fixture/docs/guide.md"
printf '{"profile":1}\n' >"$fixture/.tm/profiles/profile.json"
git -C "$fixture" add src/main.c docs/guide.md .tm/profiles/profile.json
git -C "$fixture" commit --quiet -m 'base'
base=$(git -C "$fixture" rev-parse HEAD)

printf 'updated guide\n' >"$fixture/docs/guide.md"
git -C "$fixture" commit --quiet -am 'docs only'
docs_only=$(git -C "$fixture" rev-parse HEAD)
if (cd "$fixture" && bash "$repo_root/scripts/tm-ci-has-test-changes.sh" \
    "$base" HEAD); then
    printf '%s\n' 'Documentation-only diff incorrectly requires tests.' >&2
    exit 1
else
    status=$?
    if [[ $status -ne 1 ]]; then
        printf 'Documentation-only diff returned unexpected status %s.\n' \
            "$status" >&2
        exit 1
    fi
fi
classification=$(cd "$fixture" && bash "$classify" "$base" "$docs_only")
grep -Fxq 'tests_required=false' <<<"$classification"
grep -Fxq 'has_results=false' <<<"$classification"
grep -Fxq 'results_only=false' <<<"$classification"

mkdir -p "$fixture/.tm/results/command/verification"
printf '{"schema_version":3}\n' > \
    "$fixture/.tm/results/command/verification/record.tm.json"
git -C "$fixture" add -f .tm/results
git -C "$fixture" commit --quiet -m 'result only'
results_only=$(git -C "$fixture" rev-parse HEAD)
classification=$(cd "$fixture" && bash "$classify" "$docs_only" \
    "$results_only")
grep -Fxq 'tests_required=false' <<<"$classification"
grep -Fxq 'has_results=true' <<<"$classification"
grep -Fxq 'results_only=true' <<<"$classification"

printf 'int main(void) { return 2; }\n' >"$fixture/src/main.c"
mkdir -p "$fixture/.tm/blobs/sha256"
printf 'blob\n' >"$fixture/.tm/blobs/sha256/example"
git -C "$fixture" add src/main.c
git -C "$fixture" add -f .tm/blobs/sha256/example
git -C "$fixture" commit --quiet -am 'mixed source and evidence'
mixed=$(git -C "$fixture" rev-parse HEAD)
classification=$(cd "$fixture" && bash "$classify" "$results_only" "$mixed")
grep -Fxq 'tests_required=true' <<<"$classification"
grep -Fxq 'has_results=true' <<<"$classification"
grep -Fxq 'results_only=false' <<<"$classification"

printf 'int main(void) { return 1; }\n' >"$fixture/src/main.c"
git -C "$fixture" commit --quiet -am 'source change'
if ! (cd "$fixture" && bash "$repo_root/scripts/tm-ci-has-test-changes.sh" \
    "$base" HEAD); then
    printf '%s\n' 'Source diff did not require tests.' >&2
    exit 1
fi

git -C "$fixture" checkout --quiet "$base"
printf '{"profile":2}\n' >"$fixture/.tm/profiles/profile.json"
git -C "$fixture" commit --quiet -am 'profile change'
if ! (cd "$fixture" && bash "$repo_root/scripts/tm-ci-has-test-changes.sh" \
    "$base" HEAD); then
    printf '%s\n' 'Profile-policy diff did not require tests.' >&2
    exit 1
fi

if (cd "$fixture" && bash "$repo_root/scripts/tm-ci-has-test-changes.sh" \
    missing HEAD) 2>/dev/null; then
    printf '%s\n' 'Invalid diff base was accepted.' >&2
    exit 1
else
    status=$?
    if [[ $status -ne 2 ]]; then
        printf 'Invalid diff base returned unexpected status %s.\n' \
            "$status" >&2
        exit 1
    fi
fi
if (cd "$fixture" && bash "$classify" missing HEAD) 2>/dev/null; then
    printf '%s\n' 'CI diff classifier accepted a missing base.' >&2
    exit 1
else
    status=$?
    if [[ $status -ne 2 ]]; then
        printf 'CI diff classifier returned unexpected status %s.\n' \
            "$status" >&2
        exit 1
    fi
fi
