#define _GNU_SOURCE

#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (strcmp(argv[1], "getpid") == 0)
        return syscall(SYS_getpid) > 0 ? 0 : 1;
    if (strcmp(argv[1], "prlimit") == 0) {
        struct rlimit limits;
        return syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &limits) == 0 ?
            0 : 1;
    }
    return 2;
}
