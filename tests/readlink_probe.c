#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char target[256];
    long length;

    if (argc != 3) return 2;
    errno = 0;
    length = syscall(SYS_readlink, argv[1], target, sizeof(target));
    if (strcmp(argv[2], "success") == 0) return length >= 0 ? 0 : 1;
    if (strcmp(argv[2], "missing") == 0)
        return length < 0 && errno == ENOENT ? 0 : 1;
    if (strcmp(argv[2], "error") == 0)
        return length < 0 && errno == EINVAL ? 0 : 1;
    return 2;
}
