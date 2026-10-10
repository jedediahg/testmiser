#include <stdio.h>
#include <string.h>

#include "tm/tm.h"

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tm [OPTIONS] -- COMMAND [ARGUMENT ...]\n");
    fprintf(stream, "Memoize a successful verification command (not implemented).\n");
    fprintf(stream, "Options: --force  --explain  --help\n");
}

int main(int argc, char **argv)
{
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 ||
                      strcmp(argv[1], "-h") == 0)) {
        print_usage(stdout);
        return 0;
    }

    if (argc < 2) {
        print_usage(stderr);
        return TM_EXIT_INTERNAL_ERROR;
    }

    fprintf(stderr, "tm: command execution is not implemented yet\n");
    return TM_EXIT_INTERNAL_ERROR;
}
