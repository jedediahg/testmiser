#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tm/tm.h"

struct options {
    int force;
    int explain;
    int command_index;
};

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tm [--force] [--explain] -- COMMAND [ARGUMENT ...]\n");
    fprintf(stream, "Run a verification command (result memoization is not implemented yet).\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  --force    always run the command\n");
    fprintf(stream, "  --explain  explain why the command is running\n");
    fprintf(stream, "  --help     show this help\n");
}

static int parse_options(int argc, char **argv, struct options *options)
{
    int index;

    options->force = 0;
    options->explain = 0;
    options->command_index = -1;

    for (index = 1; index < argc; index++) {
        if (strcmp(argv[index], "--") == 0) {
            options->command_index = index + 1;
            break;
        }
        if (strcmp(argv[index], "--force") == 0) {
            options->force = 1;
        } else if (strcmp(argv[index], "--explain") == 0) {
            options->explain = 1;
        } else if (strcmp(argv[index], "--help") == 0 ||
                   strcmp(argv[index], "-h") == 0) {
            print_usage(stdout);
            return 1;
        } else {
            fprintf(stderr, "tm: unknown option: %s\n", argv[index]);
            print_usage(stderr);
            return -1;
        }
    }

    if (options->command_index < 0 || options->command_index >= argc) {
        fprintf(stderr, "tm: expected -- followed by a command\n");
        print_usage(stderr);
        return -1;
    }

    return 0;
}

static int run_command(char **command)
{
    pid_t child;
    pid_t waited;
    int status;

    child = fork();
    if (child < 0) {
        perror("tm: fork");
        return TM_EXIT_INTERNAL_ERROR;
    }

    if (child == 0) {
        execvp(command[0], command);
        if (errno == ENOENT || errno == ENOTDIR) {
            fprintf(stderr, "tm: command not found: %s\n", command[0]);
            _exit(TM_EXIT_COMMAND_NOT_FOUND);
        }
        fprintf(stderr, "tm: cannot execute %s: %s\n", command[0],
                strerror(errno));
        _exit(TM_EXIT_CANNOT_EXECUTE);
    }

    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited < 0) {
        perror("tm: waitpid");
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    fprintf(stderr, "tm: could not collect child status\n");
    return TM_EXIT_INTERNAL_ERROR;
}

int main(int argc, char **argv)
{
    struct options options;
    int parse_result;

    parse_result = parse_options(argc, argv, &options);
    if (parse_result != 0) {
        return parse_result > 0 ? 0 : TM_EXIT_INTERNAL_ERROR;
    }

    if (options.explain) {
        fprintf(stderr,
                "tm: RUN: memoization is not implemented; executing command\n");
    }
    (void) options.force;

    return run_command(&argv[options.command_index]);
}
