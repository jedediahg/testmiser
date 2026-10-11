#define _GNU_SOURCE

#include <sys/auxv.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct timespec now;
    struct timeval wall;

    if (argc != 2 || getauxval(AT_SYSINFO_EHDR) != 0 ||
        getauxval(AT_SYSINFO) != 0)
        return 41;
    if (strcmp(argv[1], "clock_gettime") == 0) {
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 42;
    } else if (strcmp(argv[1], "clock_getres") == 0) {
        if (clock_getres(CLOCK_MONOTONIC, &now) != 0) return 43;
    } else if (strcmp(argv[1], "gettimeofday") == 0) {
        if (gettimeofday(&wall, NULL) != 0) return 44;
    } else if (strcmp(argv[1], "time") == 0) {
        if (time(NULL) == (time_t)-1) return 45;
    } else {
        return 46;
    }
    return 0;
}
