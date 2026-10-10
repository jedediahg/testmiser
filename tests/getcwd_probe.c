#define _GNU_SOURCE

#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
    char path[4096];
    return syscall(SYS_getcwd, path, sizeof(path)) > 0 ? 0 : 1;
}
