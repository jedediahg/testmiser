#define _GNU_SOURCE

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int consume_file(void)
{
    char byte;
    int descriptor = open("implementation-notes.md", O_RDONLY | O_CLOEXEC);
    int result;
    if (descriptor < 0) return 1;
    result = read(descriptor, &byte, 1) == 1 ? 0 : 1;
    close(descriptor);
    return result;
}

int main(int argc, char **argv)
{
    int directory, result;
    if (argc != 2) return 2;
    if (strcmp(argv[1], "chdir") == 0) {
        if (chdir("docs") < 0) return 1;
        return consume_file();
    }
    if (strcmp(argv[1], "fchdir") != 0) return 2;
    directory = open("docs", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) return 1;
    result = fchdir(directory) < 0 ? 1 : consume_file();
    close(directory);
    return result;
}
