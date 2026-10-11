#define _GNU_SOURCE

#include <sys/syscall.h>
#include <unistd.h>

static long parse_number(const char *text)
{
    long value = 0;
    if (text == 0 || *text == '\0') return -1;
    while (*text != '\0') {
        long digit;
        if (*text < '0' || *text > '9') return -1;
        digit = *text - '0';
        if (value > (1000 - digit) / 10) return -1;
        value = value * 10 + digit;
        text++;
    }
    return value;
}

int main(int argc, char **argv)
{
#if defined(__x86_64__)
    long number;
    if (argc != 2 || (number = parse_number(argv[1])) < 0) return 2;
    /* Deliberately use an invalid descriptor/domain: even a failed socket
     * operation is an external input channel and must block reuse. */
    (void)syscall(number, -1, 0, 0, 0, 0, 0);
#else
    (void)argc;
    (void)argv;
#endif
    return 0;
}
