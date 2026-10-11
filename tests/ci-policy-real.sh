#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
fixture=$work/repo
git clone --quiet --no-hardlinks --local "$repo_root" "$fixture"
git -C "$fixture" config user.name 'tm CI policy integration test'
git -C "$fixture" config user.email 'tm-ci-policy-real@localhost'

# Reuse the already-built, current tm binary for this isolated checkout so the
# test exercises real validation without recompiling the whole project.
cp -a "$repo_root/build" "$fixture/build"
cp "$repo_root/scripts/tm-ci-run-tests.sh" \
    "$repo_root/scripts/tm-ci-classify-changes.sh" \
    "$repo_root/scripts/tm-ci-has-test-changes.sh" \
    "$repo_root/scripts/tm-result-diff.sh" \
    "$repo_root/scripts/tm-ci-validate-results.sh" "$fixture/scripts/"
chmod +x "$fixture/scripts/"*.sh
base=$(git -C "$fixture" rev-parse HEAD)

command_id=$(printf 'a%.0s' {1..64})
verification_id=$(printf 'b%.0s' {1..64})
mkdir -p "$fixture/.tm/results/$command_id/$verification_id"
printf '{"schema_version":3}\n' > \
    "$fixture/.tm/results/$command_id/$verification_id/bad.tm.json"
git -C "$fixture" add -f ".tm/results/$command_id/$verification_id/bad.tm.json"
git -C "$fixture" commit --quiet -m 'invalid evidence only'
head=$(git -C "$fixture" rev-parse HEAD)

real_make=$(command -v make)
mkdir -p "$work/bin"
cat >"$work/bin/make" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$TM_CI_MAKE_LOG"
exec "$TM_CI_REAL_MAKE" "$@"
EOF
chmod +x "$work/bin/make"

set +e
(cd "$fixture" && PATH="$work/bin:$PATH" \
    TM_CI_MAKE_LOG="$work/make.log" TM_CI_REAL_MAKE="$real_make" \
    GITHUB_OUTPUT="$work/github-output" \
    bash scripts/tm-ci-run-tests.sh "$base" "$head") \
    >"$work/run.log" 2>&1
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
    cat "$work/run.log" >&2
    printf '%s\n' 'Result-only CI policy accepted malformed evidence.' >&2
    exit 1
fi
if [[ $(wc -l <"$work/make.log") -ne 1 ]] ||
   [[ $(cat "$work/make.log") != 'build/tm' ]]; then
    cat "$work/make.log" >&2
    printf '%s\n' 'Result-only policy ran tests or skipped real validation setup.' >&2
    exit 1
fi
grep -Fq 'bad.tm.json' "$work/run.log"

echo 'Real CI policy validation test passed.'
