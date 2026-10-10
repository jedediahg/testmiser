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
workspace_tmpfs=no
workspace_readonly=no
input_mount=no
expected_input_mount=no
whole_workspace_bind=no
workspace_overlay=no
readonly_runtime=no
hidden_metadata=no
clean_environment=no
user_namespace=no
namespace_uid=no
namespace_gid=no
namespace_ipc=no
namespace_pid=no
namespace_net=no
namespace_uts=no
namespace_cgroup=no
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    case "$1" in
        --unshare-all) unshare_all=yes ;;
        --unshare-user) user_namespace=yes ;;
        --unshare-ipc) namespace_ipc=yes ;;
        --unshare-pid) namespace_pid=yes ;;
        --unshare-net) namespace_net=yes ;;
        --unshare-uts) namespace_uts=yes ;;
        --unshare-cgroup) namespace_cgroup=yes ;;
        --uid)
            test "$#" -ge 2 && [ "$2" = 0 ] || fail 'namespace uid is not 0'
            namespace_uid=yes
            shift
            ;;
        --gid)
            test "$#" -ge 2 && [ "$2" = 0 ] || fail 'namespace gid is not 0'
            namespace_gid=yes
            shift
            ;;
        --die-with-parent) die_with_parent=yes ;;
        --remount-ro)
            if [ "$2" = /workspace ]; then workspace_readonly=yes; fi
            shift
            ;;
        --overlay-src|--tmp-overlay) workspace_overlay=yes ;;
        --clearenv) clean_environment=yes ;;
        --ro-bind-fd)
            if [ "$#" -lt 3 ]; then exit 90; fi
            test -d "/proc/$$/fd/$2" ||
                fail "read-only bind descriptor $2 is not inherited"
            if [ "$3" = / ]; then readonly_runtime=yes; fi
            case "$3" in
                /workspace) whole_workspace_bind=yes ;;
                /workspace/*)
                    input_mount=yes
                    if [ "$3" = /workspace/src ]; then
                        expected_input_mount=yes
                    fi
                    ;;
            esac
            shift 2
            ;;
        --ro-bind)
            if [ "$#" -lt 3 ]; then exit 90; fi
            if [ "$3" = / ]; then readonly_runtime=yes; fi
            case "$3" in
                /workspace) whole_workspace_bind=yes ;;
                /workspace/*)
                    input_mount=yes
                    if [ "$3" = /workspace/src ]; then
                        test "$2" = "$(pwd -P)/src" ||
                            fail 'input root source differs from approved checkout path'
                        expected_input_mount=yes
                    fi
                    ;;
            esac
            shift 2
            ;;
        --tmpfs)
            if [ "$#" -lt 2 ]; then exit 90; fi
            if [ "$2" = /workspace ]; then workspace_tmpfs=yes; fi
            if [ "$2" = /workspace/.tm ]; then hidden_metadata=yes; fi
            shift
            ;;
    esac
    shift
done
test "$#" -gt 1 || fail 'missing wrapped command'
if [ "$user_namespace" = yes ] || [ "$namespace_uid" = yes ] ||
    [ "$namespace_gid" = yes ]; then
    test "$user_namespace" = yes || fail '--unshare-user'
    test "$namespace_ipc" = yes || fail '--unshare-ipc'
    test "$namespace_pid" = yes || fail '--unshare-pid'
    test "$namespace_net" = yes || fail '--unshare-net'
    test "$namespace_uts" = yes || fail '--unshare-uts'
    test "$namespace_cgroup" = yes || fail '--unshare-cgroup'
    test "$namespace_uid" = yes || fail '--uid 0'
    test "$namespace_gid" = yes || fail '--gid 0'
else
    test "$unshare_all" = yes || fail 'namespace isolation is missing'
fi
test "$die_with_parent" = yes || fail '--die-with-parent'
test "$workspace_tmpfs" = yes || fail 'workspace tmpfs is missing'
test "$workspace_readonly" = yes || fail 'workspace remount is not read-only'
test "$input_mount" = yes || fail 'approved input roots are not mounted'
test "$expected_input_mount" = yes || fail 'profile input root was not mounted at its canonical path'
test "$whole_workspace_bind" = no || fail 'entire checkout is exposed'
test "$workspace_overlay" = no || fail 'writable workspace overlay is present'
test "$readonly_runtime" = yes || fail 'read-only runtime fd bind'
test "$hidden_metadata" = yes || fail 'hidden metadata tmpfs'
test "$clean_environment" = yes || fail '--clearenv'
test "$(umask)" = 0022 || fail 'profile umask is not 022'
shift
if [ "$1" = "/bin/sh" ] && [ "$4" = "tm-profile-view-probe" ]; then
    test "$2" = "-c" || fail 'profile view probe is not a shell check'
    printf '%s\n' "$3" | /bin/sh -n || fail 'profile view probe syntax'
    case "$3" in
        *"/workspace/.tm/"*"/.tm-runtime-write-probe-"*".tm-workspace-write-probe-"*"for scratch do"*) ;;
        *) fail 'profile view probe omits metadata/runtime/workspace/scratch checks' ;;
    esac
    printf 'probe\n' >>"$TM_FAKE_BWRAP_LOG"
    exit 0
else
    printf 'command\n' >>"$TM_FAKE_BWRAP_LOG"
fi
exec "$@"
