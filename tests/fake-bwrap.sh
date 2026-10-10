#!/bin/sh
set -eu

while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    shift
done
test "$#" -gt 1
shift
if [ "$1" = "/bin/true" ]; then
    printf 'probe\n' >>"$TM_FAKE_BWRAP_LOG"
else
    printf 'command\n' >>"$TM_FAKE_BWRAP_LOG"
fi
exec "$@"
