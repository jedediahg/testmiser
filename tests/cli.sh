#!/bin/sh
set -eu

tm_bin=${TM_BIN:-./build/tm}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

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

set +e
"$tm_bin" -- sh -c 'kill -TERM $$'
status=$?
set -e
test "$status" -eq 143

set +e
PATH="$tmp_dir" "$tm_bin" -- tm-command-that-does-not-exist-4f5c9a \
    >"$tmp_dir/missing.out" 2>"$tmp_dir/missing.err"
status=$?
set -e
test "$status" -eq 127
grep -q 'command not found' "$tmp_dir/missing.err"

"$tm_bin" --explain -- sh -c 'exit 0' 2>"$tmp_dir/explain.err"
grep -q 'RUN: memoization is not implemented' "$tmp_dir/explain.err"

"$tm_bin" --force -- sh -c 'exit 0'

set +e
"$tm_bin" --unknown-option -- sh -c 'exit 0' \
    >"$tmp_dir/unknown.out" 2>"$tmp_dir/unknown.err"
status=$?
set -e
test "$status" -eq 125
grep -q 'unknown option' "$tmp_dir/unknown.err"

printf '%s\n' 'CLI checks passed'
