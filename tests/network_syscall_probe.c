#define _GNU_SOURCE

#include <sys/syscall.h>
#include <unistd.h>

int main(void)
{
#if defined(__x86_64__)
    static const long socket_syscalls[] = {51, 52, 54, 55, 299, 307};
    unsigned long index;

    for (index = 0; index < sizeof(socket_syscalls) / sizeof(socket_syscalls[0]);
         index++) {
        (void)syscall(socket_syscalls[index], -1, 0, 0, 0, 0, 0);
    }
#endif
    return 0;
}
