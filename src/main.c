#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "tm/input.h"
#include "tm/clean.h"
#include "tm/identity.h"
#include "tm/outputs.h"
#include "tm/observer.h"
#include "tm/profile.h"
#include "tm/repo.h"
#include "tm/tm.h"
#include "tm/trust.h"
#include "tm/validate.h"

#define TM_MAX_EXPLICIT_INPUTS 128
#define TM_MAX_EXPLICIT_OUTPUTS 128

struct options {
    int force;
    int explain;
    const char *profile_path;
    const char *trust_policy_path;
    const char *root_path;
    const char *input_paths[TM_MAX_EXPLICIT_INPUTS];
    size_t input_count;
    const char *output_paths[TM_MAX_EXPLICIT_OUTPUTS];
    size_t output_count;
    int command_index;
};

static char **profile_environment(const struct tm_profile *profile)
{
    size_t count = tm_profile_environment_count(profile), index;
    char **environment = calloc(count + 1, sizeof(*environment));
    if (environment == NULL) return NULL;
    for (index = 0; index < count; index++) {
        const char *name = tm_profile_environment_name(profile, index);
        const char *value = tm_profile_environment_value(profile, index);
        size_t length = strlen(name) + strlen(value) + 2;
        environment[index] = malloc(length);
        if (environment[index] == NULL) {
            while (index > 0) free(environment[--index]);
            free(environment);
            return NULL;
        }
        (void)snprintf(environment[index], length, "%s=%s", name, value);
    }
    return environment;
}

static void free_environment(char **environment)
{
    size_t index;
    if (environment == NULL) return;
    for (index = 0; environment[index] != NULL; index++)
        free(environment[index]);
    free(environment);
}

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tm [--root DIR] [--input PATH ...] [--output PATH ...] [--profile FILE --trust-policy FILE] [--force] [--explain] -- COMMAND [ARGUMENT ...]\n");
    fprintf(stream, "Run a verification command (cache reuse is disabled during observer development).\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  --force    always run the command\n");
    fprintf(stream, "  TM_FORCE=1 has the same effect as --force\n");
    fprintf(stream, "  --explain  explain why the command is running\n");
    fprintf(stream, "  --profile FILE       select an approved profile (currently uncached)\n");
    fprintf(stream, "  --trust-policy FILE  load operator trust configuration\n");
    fprintf(stream, "  --root DIR           set repository root (default: nearest .git)\n");
    fprintf(stream, "  --input PATH         declare a repository-relative input file\n");
    fprintf(stream, "  --output PATH        declare a repository-relative output root\n");
    fprintf(stream, "  --help     show this help\n");
}

static int profile_command(int argc, char **argv)
{
    struct tm_profile *profile = NULL;
    int result;
    if (argc != 4 || strcmp(argv[2], "digest") != 0) {
        fprintf(stderr, "Usage: tm profile digest FILE\n");
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (tm_profile_load(argv[3], &profile) < 0) {
        fprintf(stderr, "tm: invalid profile: %s\n", argv[3]);
        return TM_EXIT_INTERNAL_ERROR;
    }
    result = printf("%s %s\n", tm_profile_repository_id(profile),
                    tm_profile_digest(profile)) < 0 ?
             TM_EXIT_INTERNAL_ERROR : 0;
    tm_profile_free(profile);
    return result;
}

static int parse_options(int argc, char **argv, struct options *options)
{
    int index;

    options->force = 0;
    options->explain = 0;
    options->profile_path = NULL;
    options->trust_policy_path = NULL;
    options->root_path = NULL;
    options->input_count = 0;
    options->output_count = 0;
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
        } else if (strcmp(argv[index], "--input") == 0) {
            const char *input_path;
            size_t input_index;
            if (index + 1 >= argc ||
                strncmp(argv[index + 1], "--", 2) == 0 ||
                options->input_count == TM_MAX_EXPLICIT_INPUTS) {
                fprintf(stderr, "tm: missing or too many --input values\n");
                return -1;
            }
            input_path = argv[++index];
            if (input_path[0] == '\0') {
                fprintf(stderr, "tm: --input path must not be empty\n");
                return -1;
            }
            for (input_index = 0; input_index < options->input_count;
                 input_index++)
                if (strcmp(options->input_paths[input_index], input_path) == 0)
                    break;
            if (input_index == options->input_count)
                options->input_paths[options->input_count++] = input_path;
        } else if (strcmp(argv[index], "--output") == 0) {
            const char *output_path;
            size_t output_index;
            if (index + 1 >= argc ||
                strncmp(argv[index + 1], "--", 2) == 0 ||
                options->output_count == TM_MAX_EXPLICIT_OUTPUTS) {
                fprintf(stderr, "tm: missing or too many --output values\n");
                return -1;
            }
            output_path = argv[++index];
            for (output_index = 0; output_index < options->output_count;
                 output_index++)
                if (strcmp(options->output_paths[output_index], output_path) == 0)
                    break;
            if (output_index == options->output_count)
                options->output_paths[options->output_count++] = output_path;
        } else if (strcmp(argv[index], "--profile") == 0 ||
                   strcmp(argv[index], "--trust-policy") == 0 ||
                   strcmp(argv[index], "--root") == 0) {
            const char *option = argv[index];
            const char **destination = strcmp(option, "--profile") == 0 ?
                &options->profile_path :
                (strcmp(option, "--trust-policy") == 0 ?
                 &options->trust_policy_path : &options->root_path);
            if (*destination != NULL || index + 1 >= argc ||
                strcmp(argv[index + 1], "--") == 0) {
                fprintf(stderr, "tm: missing or repeated value for %s\n", option);
                return -1;
            }
            *destination = argv[++index];
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
    if (tm_output_roots_validate(options->output_paths,
                                 options->output_count) < 0) {
        fprintf(stderr, "tm: invalid or overlapping --output roots\n");
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct options options;
    struct tm_profile *profile = NULL;
    struct tm_trust_policy *trust_policy = NULL;
    char **child_environment = NULL;
    const char *force_environment;
    char *repository_root = NULL;
    struct tm_input_observation explicit_inputs[TM_MAX_EXPLICIT_INPUTS];
    char explicit_input_digests[TM_MAX_EXPLICIT_INPUTS][72];
    char *explicit_input_targets[TM_MAX_EXPLICIT_INPUTS] = {0};
    const char *unavailable_inputs[TM_MAX_EXPLICIT_INPUTS];
    size_t explicit_input_count = 0, unavailable_input_count = 0, index;
    int repository_fd = -1;
    int parse_result;
    int result;

    if (argc > 1 && strcmp(argv[1], "validate") == 0)
        return tm_validate_main(argc, argv);
    if (argc > 1 && strcmp(argv[1], "clean") == 0)
        return tm_clean_main(argc, argv);
    if (argc > 1 && strcmp(argv[1], "profile") == 0)
        return profile_command(argc, argv);
    parse_result = parse_options(argc, argv, &options);
    if (parse_result != 0) {
        return parse_result > 0 ? 0 : TM_EXIT_INTERNAL_ERROR;
    }
    force_environment = getenv("TM_FORCE");
    if (force_environment != NULL && strcmp(force_environment, "1") == 0)
        options.force = 1;

    if (options.trust_policy_path != NULL &&
        tm_trust_policy_load(options.trust_policy_path, &trust_policy) < 0) {
        fprintf(stderr, "tm: invalid trust policy: %s\n",
                options.trust_policy_path);
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (options.profile_path != NULL) {
        if (tm_profile_load(options.profile_path, &profile) < 0) {
            fprintf(stderr, "tm: invalid profile: %s\n", options.profile_path);
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (trust_policy == NULL ||
            tm_trust_policy_approves_profile(trust_policy,
                tm_profile_repository_id(profile), tm_profile_digest(profile)) < 0) {
            fprintf(stderr, "tm: profile is not approved by trust policy\n");
            tm_profile_free(profile);
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (options.explain) {
            if (!tm_profile_is_deterministic(profile))
                fprintf(stderr, "tm: reuse rejected: profile does not declare deterministic results\n");
            if (strcmp(tm_profile_privacy_class(profile), "secret-dependent") == 0)
                fprintf(stderr, "tm: reuse rejected: secret-dependent profiles are not portable\n");
            fprintf(stderr, "tm: RUN: profile approved and its environment applied; portable backend is not enforced, so reuse is disabled\n");
        }
        child_environment = profile_environment(profile);
        if (child_environment == NULL) {
            fprintf(stderr, "tm: cannot construct profile environment\n");
            tm_profile_free(profile);
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
        }
    }
    if (tm_repo_root(options.root_path, &repository_root) < 0) {
        fprintf(stderr, "tm: invalid repository root: %s\n",
                options.root_path == NULL ? "." : options.root_path);
        free_environment(child_environment);
        tm_profile_free(profile);
        tm_trust_policy_free(trust_policy);
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (options.explain && profile != NULL) {
        char *current_directory = getcwd(NULL, 0);
        char *working_directory = current_directory == NULL ? NULL :
            tm_repo_relative_path(repository_root, current_directory);
        if (working_directory == NULL) {
            fprintf(stderr,
                    "tm: reuse rejected: working directory is outside the repository or unavailable\n");
        } else {
            struct tm_command_identity identity = {
                tm_profile_repository_id(profile),
                (const char *const *)&argv[options.command_index],
                (size_t)(argc - options.command_index), working_directory,
                options.input_paths, options.input_count,
                options.output_paths, options.output_count
            };
            char command_fingerprint[72];
            if (tm_command_fingerprint(&identity, command_fingerprint) == 0)
                fprintf(stderr, "tm: command fingerprint: %s\n",
                        command_fingerprint);
            else
                fprintf(stderr,
                        "tm: reuse rejected: command identity is not portable\n");
        }
        free(working_directory);
        free(current_directory);
    }
    if (options.input_count > 0) {
        repository_fd = open(repository_root,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        for (index = 0; index < options.input_count; index++) {
            const char *path = options.input_paths[index];
            enum tm_input_kind kind = TM_INPUT_FILE;
            int exists = 1;
            int captured = repository_fd >= 0 ?
                tm_input_capture_file(repository_fd, path,
                    explicit_input_digests[explicit_input_count]) : -1;
            if (captured < 0 && repository_fd >= 0) {
                kind = TM_INPUT_DIRECTORY;
                captured = tm_input_capture_directory(repository_fd, path,
                    explicit_input_digests[explicit_input_count]);
            }
            if (captured < 0 && repository_fd >= 0 &&
                tm_input_capture_symlink(repository_fd, path,
                    &explicit_input_targets[explicit_input_count]) == 0) {
                kind = TM_INPUT_SYMLINK;
                captured = 0;
            }
            if (captured < 0 && repository_fd >= 0 &&
                tm_input_capture_exists(repository_fd, path, &exists) == 0 &&
                !exists) {
                kind = TM_INPUT_EXISTS;
                captured = 0;
            }
            if (captured == 0) {
                explicit_inputs[explicit_input_count] =
                    (struct tm_input_observation){path, kind,
                        kind == TM_INPUT_EXISTS || kind == TM_INPUT_SYMLINK ? NULL :
                            explicit_input_digests[explicit_input_count],
                        explicit_input_targets[explicit_input_count], 0};
                explicit_input_count++;
            } else {
                unavailable_inputs[unavailable_input_count++] = path;
            }
        }
    }
    if (options.force && options.explain)
        fprintf(stderr, "tm: force requested; command will execute\n");
    if (options.explain && options.output_count > 0 && profile == NULL)
        fprintf(stderr, "tm: reuse rejected: --output requires an approved enforced profile\n");
    result = tm_observe_and_run(&argv[options.command_index], options.explain,
                                child_environment, repository_root);
    for (index = 0; index < explicit_input_count; index++) {
        if (tm_input_matches(repository_fd, &explicit_inputs[index]) != 0 &&
            options.explain)
            fprintf(stderr,
                    "tm: reuse rejected: declared input changed or became unsafe: %s\n",
                    explicit_inputs[index].path);
    }
    if (options.explain)
        for (index = 0; index < unavailable_input_count; index++)
            fprintf(stderr,
                    "tm: reuse rejected: declared input could not be captured: %s\n",
                    unavailable_inputs[index]);
    if (repository_fd >= 0) close(repository_fd);
    for (index = 0; index < explicit_input_count; index++)
        free(explicit_input_targets[index]);
    free_environment(child_environment);
    free(repository_root);
    tm_profile_free(profile);
    tm_trust_policy_free(trust_policy);
    return result;
}
