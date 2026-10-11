typedef unsigned long size_t;

static long syscall3(long number, long first, long second, long third)
{
    register long result __asm__("rax") = number;
    register long arg1 __asm__("rdi") = first;
    register long arg2 __asm__("rsi") = second;
    register long arg3 __asm__("rdx") = third;

    __asm__ volatile("syscall"
        : "+a"(result)
        : "D"(arg1), "S"(arg2), "d"(arg3)
        : "rcx", "r11", "memory");
    return result;
}

static size_t string_length(const char *value)
{
    size_t length = 0;
    while (value[length] != '\0') length++;
    return length;
}

static int starts_with(const char *value, const char *prefix)
{
    size_t index = 0;
    while (prefix[index] != '\0') {
        if (value[index] != prefix[index]) return 0;
        index++;
    }
    return 1;
}

static int write_all(long descriptor, const char *buffer, size_t length)
{
    size_t written = 0;
    while (written < length) {
        long result = syscall3(1, descriptor, (long)(buffer + written),
                               (long)(length - written));
        if (result == -4) continue;
        if (result <= 0) return -1;
        written += (size_t)result;
    }
    return 0;
}

int portable_main(long argc, char **argv)
{
    static const char *const forbidden[] = {
        "CI_JOB_ID=", "CI_PIPELINE_ID=", "CI_PROJECT_DIR=", "CI_JOB_TOKEN=",
        "GITHUB_RUN_ID=", "GITHUB_WORKSPACE=", "GITHUB_TOKEN="
    };
    char input[4096] = {0};
    size_t used = 0, index;
    char **environment;
    long source, destination, result;

    if (argc != 4) return 2;
    environment = argv + argc + 1;
    for (; *environment != 0; environment++) {
        for (index = 0; index < sizeof(forbidden) / sizeof(forbidden[0]);
             index++)
            if (starts_with(*environment, forbidden[index])) return 3;
    }

    source = syscall3(2, (long)argv[1], 0, 0);
    if (source < 0) return 1;
    for (;;) {
        result = syscall3(0, source, (long)(input + used),
                          (long)(sizeof(input) - used));
        if (result == -4) continue;
        if (result < 0 || (result == 0 && used == sizeof(input))) return 1;
        if (result == 0) break;
        used += (size_t)result;
    }
    if (used == 0 || input[used - 1] != '\n') return 1;
    used--;

    /* The portable acceptance fixture uses a distinct input state to model
     * a deterministic test failure and verify retry/quarantine behavior. */
    if (starts_with(input, "fail:")) return 23;

    destination = syscall3(2, (long)argv[2], 1 | 0100 | 01000 | 02000000 |
                           0400000, 0644);
    if (destination < 0) return 1;
    if (write_all(destination, argv[3], string_length(argv[3])) < 0 ||
        write_all(destination, ":", 1) < 0 ||
        write_all(destination, input, used) < 0 ||
        write_all(destination, "\n", 1) < 0 ||
        write_all(1, argv[3], string_length(argv[3])) < 0 ||
        write_all(1, ":", 1) < 0 || write_all(1, input, used) < 0 ||
        write_all(1, "\n", 1) < 0)
        return 1;
    (void)syscall3(3, destination, 0, 0);
    (void)syscall3(3, source, 0, 0);
    return 0;
}
