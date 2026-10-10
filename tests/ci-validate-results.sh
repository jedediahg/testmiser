#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
mkdir -p "$work/bin" "$work/build" "$work/scripts" \
    "$work/.tm/blobs/sha256"
cp "$repo_root/scripts/tm-ci-validate-results.sh" "$work/scripts/"
chmod +x "$work/scripts/tm-ci-validate-results.sh"

cat >"$work/bin/make" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$work/build/tm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$TM_VALIDATE_TEST_ARGS"
policy=
while (($#)); do
    if [[ "$1" == --trust-policy ]]; then
        shift
        policy=$1
        break
    fi
    shift
done
if [[ -n "$policy" && -n "${TM_VALIDATE_EXPECTED_POLICY:-}" ]]; then
    test "$(cat "$policy")" = "$TM_VALIDATE_EXPECTED_POLICY"
    test "$(stat -c '%a' "$policy")" = 600
fi
EOF
chmod +x "$work/bin/make" "$work/build/tm"
printf blob >"$work/.tm/blobs/sha256/example"
chmod 0644 "$work/.tm/blobs/sha256/example"

policy_file=$work/operator-policy.json
printf 'file policy\n' >"$policy_file"
(
    cd "$work"
    PATH="$work/bin:$PATH" \
    TM_TRUST_POLICY_FILE="$policy_file" \
    TM_VALIDATE_TEST_ARGS="$work/file-args" \
        scripts/tm-ci-validate-results.sh
)
grep -Fxq -- "$policy_file" "$work/file-args"
grep -Fxq -- '--require-trust' "$work/file-args"
test "$(stat -c '%a' "$work/.tm/blobs/sha256/example")" = 444

json_policy='{"schema_version":1,"repositories":[]}'
(
    cd "$work"
    PATH="$work/bin:$PATH" \
    TM_TRUST_POLICY_JSON="$json_policy" \
    TM_VALIDATE_EXPECTED_POLICY="$json_policy" \
    TM_VALIDATE_TEST_ARGS="$work/json-args" \
        scripts/tm-ci-validate-results.sh
)
grep -Fxq -- '--trust-policy' "$work/json-args"
grep -Fxq -- '--require-trust' "$work/json-args"

(
    cd "$work"
    PATH="$work/bin:$PATH" \
    TM_TRUST_POLICY_FILE="$policy_file" \
    TM_TRUST_POLICY_JSON="$json_policy" \
    TM_VALIDATE_TEST_ARGS="$work/conflict-args" \
        scripts/tm-ci-validate-results.sh >"$work/conflict.out" 2>&1
) && exit 1
grep -q 'Set only one of TM_TRUST_POLICY_FILE or TM_TRUST_POLICY_JSON' \
    "$work/conflict.out"
