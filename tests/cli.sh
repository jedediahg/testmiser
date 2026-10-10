#!/bin/sh
set -eu

tm_bin=${TM_BIN:-./build/tm}
openat2_probe=${OPENAT2_PROBE:-./build/openat2_probe}
open_mode_probe=${OPEN_MODE_PROBE:-./build/open_mode_probe}
network_syscall_probe=${NETWORK_SYSCALL_PROBE:-./build/network_syscall_probe}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

mkdir -p "$tmp_dir/repo/.tm/results"
"$tm_bin" --root "$tmp_dir/repo" -- /bin/true
mkdir -p "$tmp_dir/repo/.tm/results/command/verification" \
    "$tmp_dir/repo/.tm/trust" "$tmp_dir/repo/.tm/blobs/sha256"
printf record >"$tmp_dir/repo/.tm/results/command/verification/one.tm.json"
printf keep >"$tmp_dir/repo/.tm/results/command/verification/notes.txt"
printf keep >"$tmp_dir/repo/.tm/trust/policy.json"
printf keep >"$tmp_dir/repo/.tm/blobs/sha256/blob"
printf outside >"$tmp_dir/outside.tm.json"
ln -s "$tmp_dir/outside.tm.json" \
    "$tmp_dir/repo/.tm/results/command/verification/link.tm.json"
"$tm_bin" clean --root "$tmp_dir/repo"
test -f "$tmp_dir/repo/.tm/results/command/verification/one.tm.json"
"$tm_bin" clean --root "$tmp_dir/repo" --records
test ! -e "$tmp_dir/repo/.tm/results/command/verification/one.tm.json"
test -f "$tmp_dir/repo/.tm/results/command/verification/notes.txt"
test -L "$tmp_dir/repo/.tm/results/command/verification/link.tm.json"
test "$(cat "$tmp_dir/outside.tm.json")" = outside
test -f "$tmp_dir/repo/.tm/trust/policy.json"
test -f "$tmp_dir/repo/.tm/blobs/sha256/blob"
set +e
"$tm_bin" --root "$tmp_dir/missing-root" -- sh -c \
    'touch "$1"' sh "$tmp_dir/invalid-root-child" \
    >"$tmp_dir/root.err" 2>&1
status=$?
set -e
test "$status" -eq 125
test ! -e "$tmp_dir/invalid-root-child"
mkdir -p "$tmp_dir/repo/tests"
printf original >"$tmp_dir/repo/tests/explicit.txt"
"$tm_bin" --explain --root "$tmp_dir/repo" --input tests/explicit.txt -- \
    sh -c 'printf changed > "$1"' sh "$tmp_dir/repo/tests/explicit.txt" \
    2>"$tmp_dir/input-changed.err"
grep -q 'declared input changed or became unsafe: tests/explicit.txt' \
    "$tmp_dir/input-changed.err"
ln -s explicit.txt "$tmp_dir/repo/tests/link"
"$tm_bin" --explain --root "$tmp_dir/repo" --input tests/link -- \
    sh -c 'rm "$1"; ln -s other.txt "$1"' sh \
    "$tmp_dir/repo/tests/link" 2>"$tmp_dir/input-link-changed.err"
grep -q 'declared input changed or became unsafe: tests/link' \
    "$tmp_dir/input-link-changed.err"
"$tm_bin" --explain --root "$tmp_dir/repo" --input tests/missing.txt -- \
    /bin/true 2>"$tmp_dir/input-missing.err"
if grep -q 'declared input could not be captured: tests/missing.txt' \
    "$tmp_dir/input-missing.err"; then
    exit 1
fi
"$tm_bin" --explain --root "$tmp_dir/repo" --input tests/missing.txt -- \
    sh -c 'touch "$1"' sh "$tmp_dir/repo/tests/missing.txt" \
    2>"$tmp_dir/input-created.err"
grep -q 'declared input changed or became unsafe: tests/missing.txt' \
    "$tmp_dir/input-created.err"
mkdir -p "$tmp_dir/repo/tests/input-dir"
"$tm_bin" --explain --root "$tmp_dir/repo" --input tests/input-dir -- \
    sh -c 'touch "$1"' sh "$tmp_dir/repo/tests/input-dir/item" \
    2>"$tmp_dir/input-directory-changed.err"
grep -q 'declared input changed or became unsafe: tests/input-dir' \
    "$tmp_dir/input-directory-changed.err"
"$tm_bin" --explain --root "$tmp_dir/repo" --output build/reports -- \
    /bin/true 2>"$tmp_dir/output-declaration.err"
grep -q -- '--output requires an approved enforced profile' \
    "$tmp_dir/output-declaration.err"
set +e
"$tm_bin" --root "$tmp_dir/repo" --output build --output build/reports -- \
    sh -c 'touch "$1"' sh "$tmp_dir/invalid-output-child" \
    >"$tmp_dir/overlapping-output.err" 2>&1
status=$?
set -e
test "$status" -eq 125
test ! -e "$tmp_dir/invalid-output-child"
set +e
"$tm_bin" --root "$tmp_dir/repo" --output ../outside -- \
    sh -c 'touch "$1"' sh "$tmp_dir/traversal-output-child" \
    >"$tmp_dir/traversal-output.err" 2>&1
status=$?
set -e
test "$status" -eq 125
test ! -e "$tmp_dir/traversal-output-child"
"$tm_bin" validate --root "$tmp_dir/repo" >"$tmp_dir/validate-empty.out"
mkdir -p "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
printf '{}\n' >"$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bad.tm.json"
set +e
"$tm_bin" validate --root "$tmp_dir/repo" >"$tmp_dir/validate-invalid.out" 2>&1
status=$?
set -e
test "$status" -eq 1
mkfifo "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/pipe.tm.json"
set +e
timeout 3 "$tm_bin" validate --root "$tmp_dir/repo" \
    >"$tmp_dir/validate-fifo.out" 2>&1
status=$?
set -e
test "$status" -eq 1
rm "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/pipe.tm.json"
chmod 000 "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bad.tm.json"
set +e
"$tm_bin" validate --root "$tmp_dir/repo" >"$tmp_dir/validate-io.out" 2>&1
status=$?
set -e
test "$status" -eq 125

mkdir -p "$tmp_dir/validation-limit/.tm/results"
i=0
while [ "$i" -lt 4095 ]; do
    : >"$tmp_dir/validation-limit/.tm/results/entry-$i"
    i=$((i + 1))
done
set +e
"$tm_bin" validate --root "$tmp_dir/validation-limit" \
    >"$tmp_dir/validate-limit.out" 2>&1
status=$?
set -e
test "$status" -eq 125

printf '{\n' >"$tmp_dir/bad-profile.json"
set +e
"$tm_bin" --profile "$tmp_dir/bad-profile.json" --trust-policy "$tmp_dir/missing-policy.json" \
    -- sh -c 'touch "$1"' sh "$tmp_dir/profile-child-ran" \
    >"$tmp_dir/profile.err" 2>&1
status=$?
set -e
test "$status" -eq 125
test ! -e "$tmp_dir/profile-child-ran"

cat >"$tmp_dir/profile.json" <<'EOF'
{"schema_version":1,"repository_id":"sample","backend_contract":"bubblewrap-linux-x86_64-v1","runtime_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","workspace_path":"/workspace","deterministic":true,"privacy_class":"public","environment":{"LANG":"C"},"input_roots":["src","tests"],"output_roots":[],"scratch_roots":["/tmp"]}
EOF
test "$("$tm_bin" profile digest "$tmp_dir/profile.json")" = \
    'sample sha256:9594caa6d198b87e03b0dbfd5a869f6096ad69f889dd06bf10b8094cabb716dc'
cat >"$tmp_dir/policy.json" <<'EOF'
{"schema_version":1,"repositories":[{"repository_id":"sample","minimum_trust_epoch":1,"allowed_semantics":[2],"profiles":["sha256:9594caa6d198b87e03b0dbfd5a869f6096ad69f889dd06bf10b8094cabb716dc"],"keys":[],"revoked_key_ids":[]}]}
EOF
chmod 600 "$tmp_dir/policy.json"
set +e
"$tm_bin" --profile "$tmp_dir/profile.json" --trust-policy "$tmp_dir/policy.json" \
    --explain -- sh -c 'exit 17' 2>"$tmp_dir/profile-approved.err"
status=$?
set -e
test "$status" -eq 17
grep -q 'portable backend is not enforced' "$tmp_dir/profile-approved.err"
grep -q '^tm: command fingerprint: sha256:[0-9a-f]\{64\}$' \
    "$tmp_dir/profile-approved.err"
if grep -Fq "$PWD/" "$tmp_dir/profile-approved.err"; then
    printf '%s\n' 'command identity leaked an absolute checkout path' >&2
    exit 1
fi
sed 's/"deterministic":true/"deterministic":false/' \
    "$tmp_dir/profile.json" >"$tmp_dir/nondeterministic-profile.json"
nondeterministic_digest=$("$tm_bin" profile digest \
    "$tmp_dir/nondeterministic-profile.json" | cut -d ' ' -f 2)
printf '{"schema_version":1,"repositories":[{"repository_id":"sample","minimum_trust_epoch":1,"allowed_semantics":[2],"profiles":["%s"],"keys":[],"revoked_key_ids":[]}]}' \
    "$nondeterministic_digest" >"$tmp_dir/nondeterministic-policy.json"
chmod 600 "$tmp_dir/nondeterministic-policy.json"
"$tm_bin" --profile "$tmp_dir/nondeterministic-profile.json" \
    --trust-policy "$tmp_dir/nondeterministic-policy.json" --explain -- /bin/true \
    2>"$tmp_dir/nondeterministic.err"
grep -q 'profile does not declare deterministic results' \
    "$tmp_dir/nondeterministic.err"
sed 's/"privacy_class":"public"/"privacy_class":"secret-dependent"/' \
    "$tmp_dir/profile.json" >"$tmp_dir/secret-profile.json"
secret_digest=$("$tm_bin" profile digest "$tmp_dir/secret-profile.json" | cut -d ' ' -f 2)
printf '{"schema_version":1,"repositories":[{"repository_id":"sample","minimum_trust_epoch":1,"allowed_semantics":[2],"profiles":["%s"],"keys":[],"revoked_key_ids":[]}]}' \
    "$secret_digest" >"$tmp_dir/secret-policy.json"
chmod 600 "$tmp_dir/secret-policy.json"
"$tm_bin" --profile "$tmp_dir/secret-profile.json" \
    --trust-policy "$tmp_dir/secret-policy.json" --explain -- /bin/true \
    2>"$tmp_dir/secret.err"
grep -q 'secret-dependent profiles are not portable' "$tmp_dir/secret.err"
sed 's/"LANG":"C"/"LANG":"C","PATH":"\/usr\/bin:\/bin"/' \
    "$tmp_dir/profile.json" >"$tmp_dir/env-profile.json"
env_profile_digest=$("$tm_bin" profile digest "$tmp_dir/env-profile.json" | cut -d ' ' -f 2)
printf '{"schema_version":1,"repositories":[{"repository_id":"sample","minimum_trust_epoch":1,"allowed_semantics":[2],"profiles":["%s"],"keys":[],"revoked_key_ids":[]}]}' \
    "$env_profile_digest" >"$tmp_dir/env-policy.json"
chmod 600 "$tmp_dir/env-policy.json"
TM_PROFILE_TEST_SECRET=host-secret "$tm_bin" --profile "$tmp_dir/env-profile.json" \
    --trust-policy "$tmp_dir/env-policy.json" -- /bin/sh -c \
    'printf "%s|%s|%s\n" "$LANG" "$PATH" "${TM_PROFILE_TEST_SECRET-unset}"' \
    >"$tmp_dir/profile-env.out"
test "$(cat "$tmp_dir/profile-env.out")" = 'C|/usr/bin:/bin|unset'
sed 's/"LANG":"C"/"LANG":"C.UTF-8"/' "$tmp_dir/profile.json" >"$tmp_dir/unapproved-profile.json"
set +e
"$tm_bin" --profile "$tmp_dir/unapproved-profile.json" --trust-policy "$tmp_dir/policy.json" \
    -- sh -c 'touch "$1"' sh "$tmp_dir/unapproved-child-ran" \
    >"$tmp_dir/unapproved.out" 2>&1
status=$?
set -e
test "$status" -eq 125
test ! -e "$tmp_dir/unapproved-child-ran"
chmod 600 "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bad.tm.json"

"$tm_bin" --help >"$tmp_dir/help.out"
grep -q 'Usage: tm' "$tmp_dir/help.out"

"$tm_bin" -- sh -c 'printf "%s\\n" "$1"' sh 'argument with spaces' \
    >"$tmp_dir/argument.out"
test "$(cat "$tmp_dir/argument.out")" = 'argument with spaces'

mkdir -p "$tmp_dir/runtime-root/bin"
printf 'test runtime\n' >"$tmp_dir/runtime-root/bin/tool"
chmod 0755 "$tmp_dir/runtime-root/bin/tool"
runtime_digest=$("$tm_bin" runtime digest "$tmp_dir/runtime-root")
printf '%s\n' "$runtime_digest" | grep -q '^sha256:[0-9a-f]\{64\}$'
set +e
"$tm_bin" runtime digest "$tmp_dir/missing-runtime" \
    >"$tmp_dir/runtime-error.out" 2>&1
status=$?
set -e
test "$status" -eq 125

set +e
"$tm_bin" -- sh -c 'exit 23'
status=$?
set -e
test "$status" -eq 23

for expected in 125 126 127; do
    set +e
    "$tm_bin" -- /bin/sh -c "exit $expected"
    status=$?
    set -e
    test "$status" -eq "$expected"
done

set +e
"$tm_bin" -- sh -c 'kill -TERM $$'
status=$?
set -e
test "$status" -eq 143

"$tm_bin" -- sh -c '(exec sleep 30) & printf "%s\n" "$!" >"$2"; printf "%s\n" "$$" >"$1"; exec sleep 30' sh \
    "$tmp_dir/wrapper-child.pid" "$tmp_dir/wrapper-descendant.pid" \
    >"$tmp_dir/wrapper-signal.out" 2>&1 &
wrapper_pid=$!
signal_attempt=0
while { [ ! -s "$tmp_dir/wrapper-child.pid" ] ||
       [ ! -s "$tmp_dir/wrapper-descendant.pid" ]; } &&
      [ "$signal_attempt" -lt 200 ]; do
    sleep 0.01
    signal_attempt=$((signal_attempt + 1))
done
test -s "$tmp_dir/wrapper-child.pid"
wrapped_pid=$(cat "$tmp_dir/wrapper-child.pid")
wrapped_descendant_pid=$(cat "$tmp_dir/wrapper-descendant.pid")
# Let the traced command finish its exec stop before interrupting the wrapper.
sleep 0.05
kill -TERM "$wrapper_pid"
set +e
wait "$wrapper_pid"
status=$?
set -e
test "$status" -eq 143
process_is_running() {
    [ -r "/proc/$1/stat" ] || return 1
    process_state=$(sed 's/.*) //' "/proc/$1/stat" | cut -d ' ' -f 1)
    [ "$process_state" != Z ] && [ "$process_state" != X ]
}
for terminated_pid in "$wrapped_pid" "$wrapped_descendant_pid"; do
    signal_attempt=0
    while process_is_running "$terminated_pid" &&
          [ "$signal_attempt" -lt 200 ]; do
        sleep 0.01
        signal_attempt=$((signal_attempt + 1))
    done
    if process_is_running "$terminated_pid"; then
        printf '%s\n' 'wrapper interruption left a wrapped process alive' >&2
        kill -KILL "$terminated_pid" 2>/dev/null || true
        exit 1
    fi
done

set +e
"$tm_bin" -- /bin/sh -c '( /bin/sleep 0.1; printf done > "$1" ) & exit 17' \
    sh "$tmp_dir/descendant.out"
status=$?
set -e
test "$status" -eq 17
sleep 0.2
test "$(cat "$tmp_dir/descendant.out")" = done

set +e
PATH="$tmp_dir" "$tm_bin" -- tm-command-that-does-not-exist-4f5c9a \
    >"$tmp_dir/missing.out" 2>"$tmp_dir/missing.err"
status=$?
set -e
test "$status" -eq 127
grep -q 'command not found' "$tmp_dir/missing.err"

set +e
"$tm_bin" --explain -- /bin/sh -c 'exit 29' 2>"$tmp_dir/explain.err"
status=$?
set -e
test "$status" -eq 29
grep -q 'tm: RUN:' "$tmp_dir/explain.err"
if grep -q 'observer prototype' "$tmp_dir/explain.err"; then
    "$tm_bin" --explain -- /bin/cat /etc/hostname > /dev/null \
        2>"$tmp_dir/external-candidate.err"
    grep -q 'observed input candidate: .*: <external>' \
        "$tmp_dir/external-candidate.err"
    if grep -Fq '/etc/hostname' "$tmp_dir/external-candidate.err"; then
        printf '%s\n' 'explain output leaked an external host path' >&2
        exit 1
    fi
fi
if grep -q 'observer prototype' "$tmp_dir/explain.err"; then
    exec 9<"$tmp_dir/repo/tests/explicit.txt"
    "$tm_bin" --explain -- /bin/true 2>"$tmp_dir/inherited-fd.err"
    exec 9<&-
    grep -q 'inherited or untracked descriptor provenance is not modeled' \
        "$tmp_dir/inherited-fd.err"
    "$tm_bin" --explain -- "$network_syscall_probe" \
        2>"$tmp_dir/network-syscalls.err"
    grep -q 'socket or network operation observed' "$tmp_dir/network-syscalls.err"
    python_bin=$(command -v python3 || true)
    if [ -n "$python_bin" ]; then
        "$tm_bin" --explain -- "$python_bin" -c \
            'import socket; socket.socket()' 2>"$tmp_dir/network.err"
        grep -q 'socket or network operation observed' "$tmp_dir/network.err"
    fi
    "$tm_bin" --explain -- /bin/sh -c 'printf x > "$1"' \
        sh "$tmp_dir/child-write" 2>"$tmp_dir/mutation.err"
    grep -q 'filesystem mutation observed' "$tmp_dir/mutation.err"
fi

if grep -q 'observer prototype' "$tmp_dir/explain.err" &&
    "$tm_bin" --explain -- "$openat2_probe" 2>"$tmp_dir/openat2.err"; then
    if grep -q 'unsupported syscall(s):.*437' "$tmp_dir/openat2.err"; then
        printf '%s\n' 'supported read-only openat2 was classified as unsupported' >&2
        exit 1
    fi
    if grep -q 'input descriptor provenance is not modeled' "$tmp_dir/openat2.err"; then
        printf '%s\n' 'read from an observed open descriptor was classified as external' >&2
        exit 1
    fi
    grep -q 'observed input candidate: executable: ./build/openat2_probe' \
        "$tmp_dir/openat2.err"
    if grep -Fq "$PWD/" "$tmp_dir/openat2.err"; then
        printf '%s\n' 'explain output leaked an absolute checkout path' >&2
        exit 1
    fi
fi

if grep -q 'observer prototype' "$tmp_dir/explain.err"; then
    : >"$tmp_dir/open-mode-target"
    "$tm_bin" --explain -- "$open_mode_probe" "$tmp_dir/open-mode-target" \
        2>"$tmp_dir/open-mode.err"
    grep -q 'filesystem mutation observed' "$tmp_dir/open-mode.err"
fi

"$tm_bin" --force -- sh -c 'exit 0'
"$tm_bin" --force --explain -- /bin/true 2>"$tmp_dir/force-option.err"
grep -q 'tm: force requested; command will execute' "$tmp_dir/force-option.err"
TM_FORCE=1 "$tm_bin" --explain -- /bin/true 2>"$tmp_dir/force-env.err"
grep -q 'tm: force requested; command will execute' "$tmp_dir/force-env.err"
TM_FORCE=01 "$tm_bin" --explain -- /bin/true 2>"$tmp_dir/force-other.err"
if grep -q 'tm: force requested; command will execute' "$tmp_dir/force-other.err"; then
    printf '%s\n' 'non-exact TM_FORCE value enabled force mode' >&2
    exit 1
fi

set +e
"$tm_bin" --unknown-option -- sh -c 'exit 0' \
    >"$tmp_dir/unknown.out" 2>"$tmp_dir/unknown.err"
status=$?
set -e
test "$status" -eq 125
grep -q 'unknown option' "$tmp_dir/unknown.err"

printf '%s\n' 'CLI checks passed'
