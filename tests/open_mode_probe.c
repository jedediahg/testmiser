#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int descriptor;
    if (argc != 2) return 2;
    descriptor = open(argv[1], O_RDWR | O_CLOEXEC);
    if (descriptor < 0) return 1;
    close(descriptor);
    return 0;
}
