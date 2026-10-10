#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>

static int consume(int descriptor)
{
    char byte;
    return read(descriptor, &byte, 1) == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
    int source, duplicate, target, result = 0;
    if (argc != 2) return 2;
    source = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (source < 0) return 1;
    duplicate = dup(source);
    if (duplicate < 0 || consume(duplicate) < 0) result = 1;
    if (duplicate >= 0) close(duplicate);
    if (dup2(source, source) != source || consume(source) < 0) result = 1;
    target = dup2(source, 20);
    if (target < 0) result = 1;
    else {
        if (consume(target) < 0) result = 1;
        close(target);
    }
    target = dup3(source, 21, O_CLOEXEC);
    if (target < 0) result = 1;
    else {
        if (consume(target) < 0) result = 1;
        close(target);
    }
    duplicate = fcntl(source, F_DUPFD, 30);
    if (duplicate < 0 || consume(duplicate) < 0) result = 1;
    if (duplicate >= 0) close(duplicate);
    duplicate = fcntl(source, F_DUPFD_CLOEXEC, 40);
    if (duplicate < 0 || consume(duplicate) < 0) result = 1;
    if (duplicate >= 0) close(duplicate);
    close(source);
    return result;
}
