#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    struct stat metadata;

    if (argc != 2) return 2;
    if (stat(argv[1], &metadata) < 0) {
        perror("stat metadata probe");
        return 1;
    }
    return metadata.st_size < 0;
}
