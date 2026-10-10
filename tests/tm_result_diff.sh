#!/usr/bin/env bash
set -euo pipefail

script=$(cd "$(dirname "$0")/.." && pwd)/scripts/tm-result-diff.sh
repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
git -C "$repo" init -q
git -C "$repo" config user.email ci@example.invalid
git -C "$repo" config user.name "CI Test"
mkdir -p "$repo/src"
printf 'source\n' >"$repo/src/main.c"
git -C "$repo" add .
git -C "$repo" commit -qm base
base=$(git -C "$repo" rev-parse HEAD)

mkdir -p "$repo/.tm/results"
printf '{}\n' >"$repo/.tm/results/new.tm.json"
git -C "$repo" add src/main.c
git -C "$repo" add -f .tm/results/new.tm.json
git -C "$repo" commit -qm "add result"
results=$(git -C "$repo" rev-parse HEAD)
if (cd "$repo" && bash "$script" only "$base" "$results") &&
   (cd "$repo" && bash "$script" any "$base" "$results"); then :; else
    echo "result-only diff was not classified correctly" >&2
    exit 1
fi

printf 'changed\n' >>"$repo/src/main.c"
git -C "$repo" add .
git -C "$repo" commit -qm "change source"
mixed=$(git -C "$repo" rev-parse HEAD)
if (cd "$repo" && bash "$script" only "$base" "$mixed"); then
    echo "mixed source and result diff was classified as result-only" >&2
    exit 1
fi
if ! (cd "$repo" && bash "$script" any "$base" "$mixed"); then
    echo "mixed diff did not report its result change" >&2
    exit 1
fi

mkdir -p "$repo/.tm/profiles"
printf 'profile\n' >"$repo/.tm/profiles/portable.json"
git -C "$repo" add -f .tm/profiles/portable.json
git -C "$repo" commit -qm "change profile"
profile=$(git -C "$repo" rev-parse HEAD)
if (cd "$repo" && bash "$script" only "$mixed" "$profile") ||
   (cd "$repo" && bash "$script" any "$mixed" "$profile"); then
    echo "profile-only diff was classified as result metadata" >&2
    exit 1
fi
