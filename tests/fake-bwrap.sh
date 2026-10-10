#!/bin/sh
set -eu

fail() {
    printf 'invalid Bubblewrap contract: %s\n' "$1" >&2
    printf 'invalid: %s\n' "$1" >>"$TM_FAKE_BWRAP_LOG"
    exit 90
}

if [ "${TM_FAKE_BWRAP_FD+x}" = x ] &&
    [ -e "/proc/$$/fd/$TM_FAKE_BWRAP_FD" ]; then
    fail "inherited descriptor $TM_FAKE_BWRAP_FD reached Bubblewrap"
fi

unshare_all=no
die_with_parent=no
overlay_source=no
temporary_overlay=no
readonly_runtime=no
hidden_metadata=no
clean_environment=no
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    case "$1" in
        --unshare-all) unshare_all=yes ;;
        --die-with-parent) die_with_parent=yes ;;
        --overlay-src) overlay_source=yes ;;
        --tmp-overlay) temporary_overlay=yes ;;
        --clearenv) clean_environment=yes ;;
        --ro-bind)
            if [ "$#" -lt 3 ]; then exit 90; fi
            if [ "$3" = / ]; then readonly_runtime=yes; fi
            shift 2
            ;;
        --tmpfs)
            if [ "$#" -lt 2 ]; then exit 90; fi
            if [ "$2" = /workspace/.tm ]; then hidden_metadata=yes; fi
            shift
            ;;
    esac
    shift
done
test "$#" -gt 1 || fail 'missing wrapped command'
test "$unshare_all" = yes || fail '--unshare-all'
test "$die_with_parent" = yes || fail '--die-with-parent'
test "$overlay_source" = yes || fail '--overlay-src'
test "$temporary_overlay" = yes || fail '--tmp-overlay'
test "$readonly_runtime" = yes || fail 'read-only runtime bind'
test "$hidden_metadata" = yes || fail 'hidden metadata tmpfs'
test "$clean_environment" = yes || fail '--clearenv'
shift
if [ "$1" = "/bin/sh" ] && [ "$4" = "tm-profile-view-probe" ]; then
    test "$2" = "-c" || fail 'profile view probe is not a shell check'
    printf '%s\n' "$3" | /bin/sh -n || fail 'profile view probe syntax'
    case "$3" in
        *"/workspace/.tm/"*"/.tm-runtime-write-probe-"*"for scratch do"*) ;;
        *) fail 'profile view probe omits metadata/runtime/scratch checks' ;;
    esac
    printf 'probe\n' >>"$TM_FAKE_BWRAP_LOG"
    exit 0
else
    printf 'command\n' >>"$TM_FAKE_BWRAP_LOG"
fi
exec "$@"
