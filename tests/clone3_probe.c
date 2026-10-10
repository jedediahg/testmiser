#define _GNU_SOURCE

#include <errno.h>
#include <linux/sched.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    struct clone_args arguments;
    long child;
    int status;
    if (argc != 2 || (strcmp(argv[1], "independent") != 0 &&
                      strcmp(argv[1], "shared") != 0)) return 2;
    memset(&arguments, 0, sizeof(arguments));
    arguments.exit_signal = SIGCHLD;
    if (strcmp(argv[1], "shared") == 0) arguments.flags = CLONE_FILES;
    child = syscall(SYS_clone3, &arguments, sizeof(arguments));
    if (child < 0)
        return errno == ENOSYS || errno == EPERM || errno == EINVAL ? 77 : 1;
    if (child == 0) _exit(0);
    if (waitpid((pid_t)child, &status, 0) != child) return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}
