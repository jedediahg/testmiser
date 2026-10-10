#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "tm/observer.h"
#include "tm/tm.h"
#include "tm/validate.h"

struct options {
    int force;
    int explain;
    int command_index;
};

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tm [--force] [--explain] -- COMMAND [ARGUMENT ...]\n");
    fprintf(stream, "Run a verification command (cache reuse is disabled during observer development).\n");
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

int main(int argc, char **argv)
{
    struct options options;
    int parse_result;

    if (argc > 1 && strcmp(argv[1], "validate") == 0)
        return tm_validate_main(argc, argv);
    parse_result = parse_options(argc, argv, &options);
    if (parse_result != 0) {
        return parse_result > 0 ? 0 : TM_EXIT_INTERNAL_ERROR;
    }

    (void) options.force;
    return tm_observe_and_run(&argv[options.command_index], options.explain);
}
