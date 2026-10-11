#define _GNU_SOURCE

#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (strcmp(argv[1], "identity") == 0) {
        (void)syscall(SYS_getuid);
        (void)syscall(SYS_geteuid);
        (void)syscall(SYS_getgid);
        (void)syscall(SYS_getegid);
        return 0;
    }
    if (strcmp(argv[1], "getpid") == 0)
        return syscall(SYS_getpid) > 0 ? 0 : 1;
    if (strcmp(argv[1], "getppid") == 0)
        return syscall(SYS_getppid) >= 0 ? 0 : 1;
    if (strcmp(argv[1], "gettid") == 0)
        return syscall(SYS_gettid) > 0 ? 0 : 1;
    if (strcmp(argv[1], "getuid") == 0)
        return syscall(SYS_getuid) >= 0 ? 0 : 1;
    if (strcmp(argv[1], "set_tid_address") == 0) {
        int tid = 0;
        return syscall(SYS_set_tid_address, &tid) > 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "prlimit") == 0) {
        struct rlimit limits;
        return syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &limits) == 0 ?
            0 : 1;
    }
    return 2;
}
