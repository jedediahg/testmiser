#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int descriptor, result;
    void *mapping;
    if (argc != 2) return 2;
    descriptor = open(argv[1], O_RDWR | O_CLOEXEC);
    if (descriptor < 0) return 1;
    mapping = mmap(NULL, 4096, PROT_READ, MAP_SHARED, descriptor, 0);
    if (mapping == MAP_FAILED) { close(descriptor); return 3; }
    result = mprotect(mapping, 4096, PROT_READ | PROT_WRITE);
    (void)munmap(mapping, 4096);
    close(descriptor);
    return result == 0 ? 0 : 4;
}
