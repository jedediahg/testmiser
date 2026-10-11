#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int descriptor, result;
    int private_mapping;
    void *mapping;
    if (argc < 2 || argc > 3) return 2;
    private_mapping = argc == 3 && strcmp(argv[2], "private") == 0;
    if (argc == 3 && !private_mapping) return 2;
    descriptor = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) return 1;
    mapping = mmap(NULL, 4096, PROT_READ,
                   private_mapping ? MAP_PRIVATE : MAP_SHARED,
                   descriptor, 0);
    if (mapping == MAP_FAILED) { close(descriptor); return 3; }
    result = mprotect(mapping, 4096, PROT_READ | PROT_WRITE);
    if (private_mapping && result == 0)
        *(volatile unsigned char *)mapping ^= (unsigned char)1;
    (void)munmap(mapping, 4096);
    close(descriptor);
    return private_mapping ? (result == 0 ? 0 : 5) :
                             (result < 0 ? 0 : 4);
}
