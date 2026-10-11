#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stddef.h>

int main(int argc, char **argv)
{
    struct dirent *entry;
    DIR *directory;
    if (argc != 2) return 2;
    directory = opendir(argv[1]);
    if (directory == NULL) return 1;
    while ((entry = readdir(directory)) != NULL) {
        (void)entry;
    }
    return closedir(directory) < 0;
}
