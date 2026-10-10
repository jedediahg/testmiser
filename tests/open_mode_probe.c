#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>

int main(void)
{
    int descriptor = open("/etc/hostname", O_RDWR | O_CLOEXEC);
    if (descriptor < 0) return 1;
    close(descriptor);
    return 0;
}
