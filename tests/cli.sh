#!/bin/sh
set -eu

tm_bin=${TM_BIN:-./build/tm}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

mkdir -p "$tmp_dir/repo/.tm/results"
"$tm_bin" validate --root "$tmp_dir/repo" >"$tmp_dir/validate-empty.out"
mkdir -p "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
printf '{}\n' >"$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bad.tm.json"
set +e
"$tm_bin" validate --root "$tmp_dir/repo" >"$tmp_dir/validate-invalid.out" 2>&1
status=$?
set -e
test "$status" -eq 1
chmod 000 "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bad.tm.json"
set +e
"$tm_bin" validate --root "$tmp_dir/repo" >"$tmp_dir/validate-io.out" 2>&1
status=$?
set -e
test "$status" -eq 125
chmod 600 "$tmp_dir/repo/.tm/results/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/bad.tm.json"

"$tm_bin" --help >"$tmp_dir/help.out"
grep -q 'Usage: tm' "$tmp_dir/help.out"

"$tm_bin" -- sh -c 'printf "%s\\n" "$1"' sh 'argument with spaces' \
    >"$tmp_dir/argument.out"
test "$(cat "$tmp_dir/argument.out")" = 'argument with spaces'

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

"$tm_bin" --force -- sh -c 'exit 0'

set +e
"$tm_bin" --unknown-option -- sh -c 'exit 0' \
    >"$tmp_dir/unknown.out" 2>"$tmp_dir/unknown.err"
status=$?
set -e
test "$status" -eq 125
grep -q 'unknown option' "$tmp_dir/unknown.err"

printf '%s\n' 'CLI checks passed'
