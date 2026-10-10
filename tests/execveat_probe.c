#define _GNU_SOURCE

#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
#if defined(__x86_64__)
    const char *path = "/bin/true";
    int flags = 0;
    char *arguments[] = {"true", NULL};
    if (argc > 1 && strcmp(argv[1], "empty-path") == 0) {
        path = "";
        flags = AT_EMPTY_PATH;
    }
    (void)syscall(SYS_execveat, AT_FDCWD, path, arguments, environ, flags);
#endif
    return 100;
}
