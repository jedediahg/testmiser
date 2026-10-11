#define _GNU_SOURCE

#include <sys/auxv.h>
#include <time.h>

int main(void)
{
    struct timespec now;

    if (getauxval(AT_SYSINFO_EHDR) != 0) return 41;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 42;
    return 0;
}
