#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    struct open_how how = {
        .flags = O_RDONLY | O_CLOEXEC,
        .mode = 0,
        .resolve = 0
    };
    char byte;
    ssize_t count;
    long descriptor = syscall(SYS_openat2, AT_FDCWD, "/etc/hostname", &how,
                              sizeof(how));
    if (descriptor < 0) return 1;
    do {
        count = read((int)descriptor, &byte, 1);
    } while (count < 0 && errno == EINTR);
    close((int)descriptor);
    return count == 1 ? 0 : 1;
}
