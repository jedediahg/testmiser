static long syscall3(long number, long first, long second, long third)
{
    long result;
    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static int equals(const char *left, const char *right)
{
    while (*left != '\0' && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

__attribute__((noreturn)) void tm_device_probe_start(long *stack)
{
    static const char null_path[] = "/dev/null";
    static const char random_path[] = "/dev/urandom";
    static const char null_mode[] = "null";
    static const char random_mode[] = "random";
    unsigned char byte = 0;
    char **arguments = (char **)(stack + 1);
    const char *path;
    long descriptor, result, status = 1;

    if (stack[0] != 2) goto done;
    if (equals(arguments[1], null_mode)) path = null_path;
    else if (equals(arguments[1], random_mode)) path = random_path;
    else goto done;

    descriptor = syscall3(257, -100, (long)path,
                          equals(arguments[1], null_mode) ? 1 : 0);
    if (descriptor < 0) goto done;
    if (equals(arguments[1], null_mode)) {
        result = syscall3(1, descriptor, (long)&byte, 1);
        if (result != 1) goto close_descriptor;
        if (syscall3(0, 0, (long)&byte, 1) == 0) status = 0;
    } else {
        result = syscall3(0, descriptor, (long)&byte, 1);
        if (result == 1) status = 0;
    }
close_descriptor:
    if (syscall3(3, descriptor, 0, 0) < 0) status = 1;
done:
    (void)syscall3(231, status, 0, 0);
    __builtin_unreachable();
}
