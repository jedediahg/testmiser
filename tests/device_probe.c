#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <unistd.h>

int main(void)
{
    unsigned char byte;
    int descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return 1;
    if (read(descriptor, &byte, sizeof(byte)) != (ssize_t)sizeof(byte)) {
        close(descriptor);
        return 1;
    }
    return close(descriptor) < 0;
}
