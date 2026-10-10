#define _GNU_SOURCE

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
    long descriptor = syscall(SYS_openat2, AT_FDCWD, "/etc/hostname", &how,
                              sizeof(how));
    if (descriptor < 0) return 1;
    (void)read((int)descriptor, &byte, 1);
    close((int)descriptor);
    return 0;
}
