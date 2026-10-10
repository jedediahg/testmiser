#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    char input[4096];
    size_t used = 0;
    int source, destination, result = 1;
    if (argc != 4) return 2;
    if (getenv("CI_JOB_ID") != NULL || getenv("CI_PIPELINE_ID") != NULL ||
        getenv("CI_PROJECT_DIR") != NULL || getenv("CI_JOB_TOKEN") != NULL ||
        getenv("GITHUB_RUN_ID") != NULL || getenv("GITHUB_WORKSPACE") != NULL ||
        getenv("GITHUB_TOKEN") != NULL) return 3;
    source = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source < 0) return 1;
    for (;;) {
        ssize_t count = read(source, input + used, sizeof(input) - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || (count == 0 && used == sizeof(input))) goto done;
        if (count == 0) break;
        used += (size_t)count;
    }
    if (used == 0 || input[used - 1] != '\n') goto done;
    input[used - 1] = '\0';
    destination = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
                                  O_NOFOLLOW, 0644);
    if (destination < 0) goto done;
    if (dprintf(destination, "%s:%s\n", argv[3], input) < 0) {
        close(destination);
        goto done;
    }
    if (close(destination) < 0 || dprintf(STDOUT_FILENO, "%s:%s\n",
                                          argv[3], input) < 0)
        goto done;
    result = 0;
done:
    close(source);
    return result;
}
