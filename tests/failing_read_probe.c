#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char buffer[256];
    int descriptor;
    if (argc != 3) return 2;
    descriptor = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return 3;
    for (;;) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { close(descriptor); return 4; }
        if (count == 0) break;
    }
    if (close(descriptor) < 0) return 5;
    return atoi(argv[2]);
}
