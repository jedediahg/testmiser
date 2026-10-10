#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    int descriptor;
    if (mkdir("build/tm-observer-output-test", 0700) < 0 ||
        mkdir("build/tm-observer-output-test/sub", 0700) < 0)
        return 1;
    descriptor = open("build/tm-observer-output-test/sub/report",
                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) return 1;
    if (write(descriptor, "data", 4) != 4) {
        close(descriptor);
        return 1;
    }
    return close(descriptor) == 0 ? 0 : 1;
}
