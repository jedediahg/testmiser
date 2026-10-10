#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int descriptor;
    if (argc != 2) return 2;
    if (strcmp(argv[1], "directory-write") == 0) {
        descriptor = open("docs", O_WRONLY | O_CLOEXEC);
        if (descriptor >= 0) {
            close(descriptor);
            return 1;
        }
        return errno == EISDIR ? 0 : 1;
    }
    if (strcmp(argv[1], "absent") != 0) return 2;
    descriptor = open("tm-known-absent-input-for-test", O_RDONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        close(descriptor);
        return 1;
    }
    return errno == ENOENT ? 0 : 1;
}
