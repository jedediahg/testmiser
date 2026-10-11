#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
fixture=$work/repo
mkdir -p "$fixture/scripts" "$fixture/bin" "$fixture/build" \
    "$fixture/src" \
    "$fixture/.tm/results/command/verification"
git -C "$fixture" init --quiet
git -C "$fixture" config user.name 'tm CI policy test'
git -C "$fixture" config user.email 'tm-ci-policy@localhost'
cp "$repo_root/scripts/tm-ci-run-tests.sh" \
    "$repo_root/scripts/tm-ci-classify-changes.sh" \
    "$repo_root/scripts/tm-ci-has-test-changes.sh" \
    "$repo_root/scripts/tm-result-diff.sh" \
    "$repo_root/scripts/tm-ci-validate-results.sh" "$fixture/scripts/"
chmod +x "$fixture/scripts/"*.sh

cat >"$fixture/bin/make" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == -C ]]; then shift 2; fi
printf '%s\n' "$*" >>"$TM_CI_MAKE_LOG"
EOF
cat >"$fixture/build/tm" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$TM_CI_VALIDATE_LOG"
[[ "${TM_CI_VALIDATE_FAIL:-0}" != 1 ]]
EOF
chmod +x "$fixture/bin/make" "$fixture/build/tm"
printf 'source v1\n' >"$fixture/src/source.c"
printf 'docs v1\n' >"$fixture/guide.md"
printf '{"record":1}\n' >"$fixture/.tm/results/command/verification/record.tm.json"
git -C "$fixture" add src/source.c guide.md
git -C "$fixture" add -f .tm/results/command/verification/record.tm.json
git -C "$fixture" commit --quiet -m base
base=$(git -C "$fixture" rev-parse HEAD)

# A result-only update skips test execution but always validates the evidence.
printf '{"record":2}\n' >"$fixture/.tm/results/command/verification/record.tm.json"
git -C "$fixture" add .tm/results
git -C "$fixture" commit --quiet -m evidence
evidence=$(git -C "$fixture" rev-parse HEAD)
: >"$work/make.log"
: >"$work/validate.log"
(cd "$work" && PATH="$fixture/bin:$PATH" \
    TM_CI_MAKE_LOG="$work/make.log" TM_CI_VALIDATE_LOG="$work/validate.log" \
    GITHUB_OUTPUT="$work/github-output" \
    bash "$fixture/scripts/tm-ci-run-tests.sh" "$base" "$evidence")
grep -Fqx 'build/tm' "$work/make.log"
grep -Fq 'validate --root . --require-trust' "$work/validate.log"
grep -Fxq 'tests_required=false' "$work/github-output"
grep -Fxq 'has_results=true' "$work/github-output"
grep -Fxq 'results_only=true' "$work/github-output"

# A mixed source/evidence update runs tests, analysis, and strict validation.
printf 'source v2\n' >"$fixture/src/source.c"
printf '{"record":3}\n' >"$fixture/.tm/results/command/verification/record.tm.json"
git -C "$fixture" add src/source.c .tm/results
git -C "$fixture" commit --quiet -m mixed
mixed=$(git -C "$fixture" rev-parse HEAD)
: >"$work/make.log"
: >"$work/validate.log"
(cd "$fixture" && PATH="$fixture/bin:$PATH" \
    TM_CI_MAKE_LOG="$work/make.log" TM_CI_VALIDATE_LOG="$work/validate.log" \
    GITHUB_OUTPUT="$work/github-output" \
    bash scripts/tm-ci-run-tests.sh "$evidence" "$mixed")
diff -u <(printf '%s\n' 'clean test' 'analyze' 'build/tm') "$work/make.log"
grep -Fq 'validate --root . --require-trust' "$work/validate.log"
grep -Fxq 'tests_required=true' "$work/github-output"
grep -Fxq 'has_results=true' "$work/github-output"
grep -Fxq 'results_only=false' "$work/github-output"

# A documentation-only change skips both tests and evidence validation.
printf 'docs v2\n' >"$fixture/guide.md"
git -C "$fixture" add guide.md
git -C "$fixture" commit --quiet -m docs
docs=$(git -C "$fixture" rev-parse HEAD)
: >"$work/make.log"
: >"$work/validate.log"
(cd "$fixture" && PATH="$fixture/bin:$PATH" \
    TM_CI_MAKE_LOG="$work/make.log" TM_CI_VALIDATE_LOG="$work/validate.log" \
    GITHUB_OUTPUT="$work/github-output" \
    bash scripts/tm-ci-run-tests.sh "$mixed" "$docs")
test ! -s "$work/make.log"
test ! -s "$work/validate.log"
grep -Fxq 'tests_required=false' "$work/github-output"
grep -Fxq 'has_results=false' "$work/github-output"
grep -Fxq 'results_only=false' "$work/github-output"

# Even on a result-only diff, a failed strict validation fails the job.
set +e
(cd "$fixture" && PATH="$fixture/bin:$PATH" \
    TM_CI_MAKE_LOG="$work/make.log" TM_CI_VALIDATE_LOG="$work/validate.log" \
    TM_CI_VALIDATE_FAIL=1 \
    bash scripts/tm-ci-run-tests.sh "$base" "$evidence") \
    >"$work/failure.log" 2>&1
status=$?
set -e
test "$status" -ne 0
grep -Fq 'validate --root . --require-trust' "$work/validate.log"

echo 'CI policy tests passed.'
