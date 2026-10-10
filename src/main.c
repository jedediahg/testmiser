#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "tm/input.h"
#include "tm/backend.h"
#include "tm/attestation.h"
#include "tm/clean.h"
#include "tm/context.h"
#include "tm/identity.h"
#include "tm/key.h"
#include "tm/json.h"
#include "tm/outputs.h"
#include "tm/observer.h"
#include "tm/profile.h"
#include "tm/repo.h"
#include "tm/result.h"
#include "tm/runtime.h"
#include "tm/snapshot.h"
#include "tm/tm.h"
#include "tm/trust.h"
#include "tm/verification.h"
#include "tm/validate.h"

#define TM_MAX_EXPLICIT_INPUTS 128
#define TM_MAX_EXPLICIT_OUTPUTS 128

struct options {
    int force;
    int explain;
    const char *profile_path;
    const char *trust_policy_path;
    const char *signing_key_path;
    const char *root_path;
    const char *input_paths[TM_MAX_EXPLICIT_INPUTS];
    size_t input_count;
    const char *output_paths[TM_MAX_EXPLICIT_OUTPUTS];
    size_t output_count;
    int command_index;
};

static void free_environment(char **environment);

static char **profile_environment(const struct tm_profile *profile)
{
    static const char *const default_names[] = {"HOME", "TMPDIR", "PATH"};
    const char *default_values[3] = {NULL, NULL, "/usr/bin:/bin"};
    size_t count = tm_profile_environment_count(profile), index, extra = 0;
    size_t scratch_count = tm_profile_scratch_root_count(profile);
    const char *home = NULL, *tmpdir = NULL, *scratch = NULL;
    int defaults_allowed = 0, home_allowed = 0, tmpdir_allowed = 0;
    char **environment;

    if (scratch_count > 0) {
        scratch = tm_profile_scratch_root(profile, 0);
        home = scratch;
        tmpdir = scratch;
        for (index = 0; index < count; index++) {
            const char *name = tm_profile_environment_name(profile, index);
            const char *value = tm_profile_environment_value(profile, index);
            if (strcmp(name, "HOME") == 0) home = value;
            if (strcmp(name, "TMPDIR") == 0) tmpdir = value;
        }
        for (index = 0; index < scratch_count; index++) {
            const char *root = tm_profile_scratch_root(profile, index);
            if (strcmp(home, root) == 0) home_allowed = 1;
            if (strcmp(tmpdir, root) == 0) tmpdir_allowed = 1;
        }
        defaults_allowed = home_allowed && tmpdir_allowed;
        default_values[0] = scratch;
        default_values[1] = scratch;
    }
    if (defaults_allowed)
        for (index = 0; index < sizeof(default_names) / sizeof(default_names[0]);
             index++) {
            size_t env_index;
            for (env_index = 0; env_index < count; env_index++)
                if (strcmp(tm_profile_environment_name(profile, env_index),
                           default_names[index]) == 0) break;
            if (env_index == count) extra++;
        }
    if (count > SIZE_MAX - extra - 1) return NULL;
    environment = calloc(count + extra + 1, sizeof(*environment));
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
    if (defaults_allowed) {
        size_t default_index;
        for (default_index = 0;
             default_index < sizeof(default_names) / sizeof(default_names[0]);
             default_index++) {
            size_t env_index;
            const char *name = default_names[default_index];
            const char *value = default_values[default_index];
            size_t length;
            for (env_index = 0; env_index < count; env_index++)
                if (strcmp(tm_profile_environment_name(profile, env_index),
                           name) == 0) break;
            if (env_index != count) continue;
            length = strlen(name) + strlen(value) + 2;
            environment[index] = malloc(length);
            if (environment[index] == NULL) {
                free_environment(environment);
                return NULL;
            }
            (void)snprintf(environment[index++], length, "%s=%s", name,
                           value);
        }
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

static struct tm_json_value *environment_json(char *const *environment)
{
    struct tm_json_value *object = tm_json_new_object();
    size_t index;
    if (object == NULL) return NULL;
    for (index = 0; environment != NULL && environment[index] != NULL;
         index++) {
        char *separator = strchr(environment[index], '=');
        struct tm_json_value *value;
        char *name;
        if (separator == NULL) { tm_json_free(object); return NULL; }
        name = strndup(environment[index], (size_t)(separator - environment[index]));
        if (name == NULL) { tm_json_free(object); return NULL; }
        value = tm_json_new_string(separator + 1);
        if (value == NULL || tm_json_object_set(object, name, value) < 0) {
            tm_json_free(value);
            free(name);
            tm_json_free(object);
            return NULL;
        }
        free(name);
    }
    return object;
}

static int verify_selected_runtime(const struct tm_profile *profile,
                                  int explain)
{
    const char *root = getenv("TM_RUNTIME_ROOT");
    char actual[72];
    if (root == NULL) {
        if (explain)
            fprintf(stderr,
                "tm: reuse rejected: TM_RUNTIME_ROOT is unset and the portable backend is not enforced\n");
        return 0;
    }
    if (root[0] == '\0') {
        fprintf(stderr, "tm: TM_RUNTIME_ROOT must not be empty\n");
        return -1;
    }
    if (tm_runtime_tree_digest(root, actual) < 0) {
        fprintf(stderr, "tm: invalid TM_RUNTIME_ROOT: %s\n", strerror(errno));
        return -1;
    }
    if (strcmp(actual, tm_profile_runtime_digest(profile)) != 0) {
        fprintf(stderr,
                "tm: TM_RUNTIME_ROOT does not match the approved profile\n");
        return -1;
    }
    if (explain)
        fprintf(stderr,
            "tm: runtime identity matches the approved profile\n");
    return 0;
}

static void print_usage(FILE *stream)
{
    fprintf(stream, "Usage: tm [--root DIR] [--input PATH ...] [--output PATH ...] [--profile FILE --trust-policy FILE] [--force] [--explain] -- COMMAND [ARGUMENT ...]\n");
    fprintf(stream, "       tm --version\n");
    fprintf(stream, "       tm key generate PRIVATE_KEY_FILE\n");
    fprintf(stream, "                         create a local Ed25519 producer key\n");
    fprintf(stream, "Run a verification command (cache reuse is disabled during observer development).\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  --force    always run the command\n");
    fprintf(stream, "  TM_FORCE=1 has the same effect as --force\n");
    fprintf(stream, "  --explain  explain why the command is running\n");
    fprintf(stream, "  --profile FILE       select an approved profile (currently uncached)\n");
    fprintf(stream, "  --trust-policy FILE  load operator trust configuration\n");
    fprintf(stream, "  --signing-key FILE   sign eligible controlled-profile successes\n");
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

static int runtime_command(int argc, char **argv)
{
    char digest[72];
    if (argc == 6 && strcmp(argv[2], "verify") == 0) {
        struct tm_profile *profile = NULL;
        struct tm_trust_policy *policy = NULL;
        int result = TM_EXIT_INTERNAL_ERROR;
        if (tm_profile_load(argv[3], &profile) < 0 ||
            tm_trust_policy_load(argv[4], &policy) < 0 ||
            tm_trust_policy_approves_profile(policy,
                tm_profile_repository_id(profile),
                tm_profile_digest(profile)) < 0) {
            fprintf(stderr, "tm: runtime profile or approval is invalid\n");
            goto verify_done;
        }
        if (tm_runtime_tree_digest(argv[5], digest) < 0) {
            fprintf(stderr, "tm: cannot digest runtime tree: %s\n",
                    strerror(errno));
            goto verify_done;
        }
        if (strcmp(digest, tm_profile_runtime_digest(profile)) != 0) {
            fprintf(stderr,
                    "tm: runtime tree does not match the approved profile\n");
            goto verify_done;
        }
        result = printf("runtime identity verified: %s\n", digest) < 0 ?
                 TM_EXIT_INTERNAL_ERROR : 0;
verify_done:
        tm_profile_free(profile);
        tm_trust_policy_free(policy);
        return result;
    }
    if (argc != 4 || strcmp(argv[2], "digest") != 0) {
        fprintf(stderr, "Usage: tm runtime digest ROOTFS_DIR\n"
                        "       tm runtime verify PROFILE TRUST_POLICY ROOTFS_DIR\n");
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (tm_runtime_tree_digest(argv[3], digest) < 0) {
        fprintf(stderr, "tm: cannot digest runtime tree: %s\n",
                strerror(errno));
        return TM_EXIT_INTERNAL_ERROR;
    }
    return printf("%s\n", digest) < 0 ? TM_EXIT_INTERNAL_ERROR : 0;
}

static int parse_options(int argc, char **argv, struct options *options)
{
    int index;

    options->force = 0;
    options->explain = 0;
    options->profile_path = NULL;
    options->trust_policy_path = NULL;
    options->signing_key_path = NULL;
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
                   strcmp(argv[index], "--root") == 0 ||
                   strcmp(argv[index], "--signing-key") == 0) {
            const char *option = argv[index];
            const char **destination = strcmp(option, "--profile") == 0 ?
                &options->profile_path :
                (strcmp(option, "--trust-policy") == 0 ?
                 &options->trust_policy_path :
                 (strcmp(option, "--root") == 0 ? &options->root_path :
                  &options->signing_key_path));
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

static int find_profile_cache_hit(int repository_fd,
                                  const struct tm_profile *profile,
                                  const char *runtime_root,
                                  const char *repository_root,
                                  const char *command_fingerprint,
                                  const char *context_fingerprint,
                                  const struct tm_trust_policy *trust_policy,
                                  char record_id[72])
{
    struct tm_snapshot *snapshot = NULL;
    const char **root_paths = NULL;
    int *root_descriptors = NULL;
    unsigned char *record = NULL;
    size_t record_length = 0, root_count, index;
    int preflight, found = 1;
    root_count = tm_profile_input_root_count(profile);
    if (root_count > 0) {
        root_paths = calloc(root_count, sizeof(*root_paths));
        root_descriptors = malloc(root_count * sizeof(*root_descriptors));
        if (root_descriptors != NULL)
            for (index = 0; index < root_count; index++)
                root_descriptors[index] = -1;
        if (root_paths == NULL || root_descriptors == NULL) goto done;
        for (index = 0; index < root_count; index++) {
            root_paths[index] = tm_profile_input_root(profile, index);
        }
        if (tm_snapshot_create(repository_fd, root_paths, root_count,
                               &snapshot) < 0) goto done;
        for (index = 0; index < root_count; index++) {
            root_descriptors[index] = tm_snapshot_open_root_readable(
                snapshot, index);
            if (root_descriptors[index] < 0) goto done;
        }
    }
    preflight = tm_backend_preflight(profile, runtime_root, repository_root,
                                     snapshot);
    if (preflight != 1) goto done;
    found = tm_result_find_matching_snapshot_inputs(repository_fd,
        command_fingerprint, tm_profile_digest(profile),
        tm_profile_runtime_digest(profile), context_fingerprint,
        trust_policy, root_paths, root_descriptors, root_count,
        &record, &record_length, record_id);
    if (found == 0) found = 0;
    else found = 1;
done:
    if (root_descriptors != NULL)
        for (index = 0; index < root_count; index++)
            if (root_descriptors[index] >= 0) close(root_descriptors[index]);
    free(record);
    tm_snapshot_free(snapshot);
    free(root_descriptors);
    free(root_paths);
    return found;
}

int main(int argc, char **argv)
{
    struct options options;
    struct tm_profile *profile = NULL;
    struct tm_trust_policy *trust_policy = NULL;
    struct tm_observer_report observer_report = {0};
    struct tm_observed_input_manifest observed_inputs = {0};
    struct tm_output_manifest output_manifest = {0};
    EVP_PKEY *signing_key = NULL;
    char **child_environment = NULL;
    const char *force_environment;
    const char *runtime_root = NULL;
    char *repository_root = NULL;
    char *working_directory = NULL;
    char command_fingerprint[72] = {0};
    char context_fingerprint[72] = {0};
    char signing_key_id[72] = {0};
    uint64_t signing_epoch = 0;
    struct tm_input_observation explicit_inputs[TM_MAX_EXPLICIT_INPUTS];
    char explicit_input_digests[TM_MAX_EXPLICIT_INPUTS][72];
    char *explicit_input_targets[TM_MAX_EXPLICIT_INPUTS] = {0};
    const char *unavailable_inputs[TM_MAX_EXPLICIT_INPUTS];
    size_t explicit_input_count = 0, unavailable_input_count = 0, index;
    int repository_fd = -1;
    int backend_used = 0;
    int reusable_context = 0;
    int explicit_inputs_unchanged = 1;
    int cache_hit = 0;
    int parse_result;
    int result;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("tm %s\n", TM_VERSION);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "validate") == 0)
        return tm_validate_main(argc, argv);
    if (argc > 1 && strcmp(argv[1], "clean") == 0)
        return tm_clean_main(argc, argv);
    if (argc > 1 && strcmp(argv[1], "profile") == 0)
        return profile_command(argc, argv);
    if (argc > 1 && strcmp(argv[1], "runtime") == 0)
        return runtime_command(argc, argv);
    if (argc > 1 && strcmp(argv[1], "key") == 0) {
        if (argc != 4 || strcmp(argv[2], "generate") != 0) {
            fprintf(stderr, "Usage: tm key generate PRIVATE_KEY_FILE\n");
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (tm_key_generate(argv[3]) < 0) {
            fprintf(stderr, "tm: cannot create private key %s: %s\n",
                    argv[3], strerror(errno));
            return TM_EXIT_INTERNAL_ERROR;
        }
        return 0;
    }
    parse_result = parse_options(argc, argv, &options);
    if (parse_result != 0) {
        return parse_result > 0 ? 0 : TM_EXIT_INTERNAL_ERROR;
    }
    force_environment = getenv("TM_FORCE");
    if (force_environment != NULL && strcmp(force_environment, "1") == 0)
        options.force = 1;

    if (options.signing_key_path != NULL &&
        (options.profile_path == NULL || options.trust_policy_path == NULL)) {
        fprintf(stderr,
                "tm: --signing-key requires --profile and --trust-policy\n");
        return TM_EXIT_INTERNAL_ERROR;
    }

    if (options.trust_policy_path != NULL &&
        tm_trust_policy_load(options.trust_policy_path, &trust_policy) < 0) {
        fprintf(stderr, "tm: invalid trust policy: %s\n",
                options.trust_policy_path);
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (options.profile_path != NULL) {
        runtime_root = getenv("TM_RUNTIME_ROOT");
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
        for (index = 0; index < options.input_count; index++)
            if (!tm_profile_allows_input_path(profile,
                                               options.input_paths[index])) {
                fprintf(stderr,
                    "tm: profile does not permit declared input: %s\n",
                    options.input_paths[index]);
                tm_profile_free(profile);
                tm_trust_policy_free(trust_policy);
                return TM_EXIT_INTERNAL_ERROR;
            }
        for (index = 0; index < options.output_count; index++)
            if (!tm_profile_allows_output_path(profile,
                                                options.output_paths[index])) {
                fprintf(stderr,
                    "tm: profile does not permit declared output: %s\n",
                    options.output_paths[index]);
                tm_profile_free(profile);
                tm_trust_policy_free(trust_policy);
                return TM_EXIT_INTERNAL_ERROR;
            }
        if (verify_selected_runtime(profile, options.explain) < 0) {
            tm_profile_free(profile);
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (options.signing_key_path != NULL) {
            if (tm_key_load_private(options.signing_key_path,
                                    &signing_key) < 0 ||
                tm_ed25519_key_id(signing_key, signing_key_id) < 0 ||
                tm_trust_policy_producer_epoch(trust_policy,
                    tm_profile_repository_id(profile),
                    tm_profile_digest(profile), signing_key_id,
                    &signing_epoch) < 0) {
                fprintf(stderr,
                    "tm: signing requires a protected key approved for this profile\n");
                EVP_PKEY_free(signing_key);
                tm_profile_free(profile);
                tm_trust_policy_free(trust_policy);
                return TM_EXIT_INTERNAL_ERROR;
            }
        }
        if (options.explain) {
            if (!tm_profile_is_deterministic(profile))
                fprintf(stderr, "tm: reuse rejected: profile does not declare deterministic results\n");
            if (strcmp(tm_profile_privacy_class(profile), "secret-dependent") == 0)
                fprintf(stderr, "tm: reuse rejected: secret-dependent profiles are not portable\n");
            fprintf(stderr, "tm: RUN: profile approved; reuse remains disabled until trusted lookup, output restoration, and complete equivalence are integrated\n");
        }
        child_environment = profile_environment(profile);
        if (child_environment == NULL) {
            fprintf(stderr, "tm: cannot construct profile environment\n");
            tm_profile_free(profile);
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (options.explain || signing_key != NULL || !options.force) {
            struct tm_json_value *environment =
                environment_json(child_environment);
            struct tm_json_value *execution_context = NULL;
            struct tm_json_value *profile_context = NULL;
            char *bubblewrap_path = NULL;
            char bubblewrap_digest[72];
            if (environment == NULL ||
                tm_backend_executable_identity(&bubblewrap_path,
                                               bubblewrap_digest) < 0 ||
                tm_context_capture_linux(&execution_context) < 0 ||
                tm_context_project_bubblewrap(execution_context,
                    tm_profile_backend_contract(profile),
                    bubblewrap_digest,
                    &profile_context) < 0 ||
                tm_context_fingerprint(environment, profile_context,
                                      context_fingerprint) < 0) {
                if (options.explain || signing_key != NULL)
                    fprintf(stderr,
                        "tm: reuse rejected: trusted Bubblewrap executable and Linux execution context could not be fingerprinted\n");
                if (signing_key != NULL) {
                    free(bubblewrap_path);
                    tm_json_free(profile_context);
                    tm_json_free(execution_context);
                    tm_json_free(environment);
                    free_environment(child_environment);
                    EVP_PKEY_free(signing_key);
                    tm_profile_free(profile);
                    tm_trust_policy_free(trust_policy);
                    return TM_EXIT_INTERNAL_ERROR;
                }
            } else {
                reusable_context = 1;
                if (options.explain)
                    fprintf(stderr, "tm: context fingerprint: %s (lookup remains disabled)\n",
                            context_fingerprint);
            }
            free(bubblewrap_path);
            tm_json_free(profile_context);
            tm_json_free(execution_context);
            tm_json_free(environment);
        }
    }
    if (tm_repo_root(options.root_path, &repository_root) < 0) {
        fprintf(stderr, "tm: invalid repository root: %s\n",
                options.root_path == NULL ? "." : options.root_path);
        free_environment(child_environment);
        EVP_PKEY_free(signing_key);
        tm_profile_free(profile);
        tm_trust_policy_free(trust_policy);
        return TM_EXIT_INTERNAL_ERROR;
    }
    if ((options.explain || signing_key != NULL || !options.force) &&
        profile != NULL) {
        char *current_directory = getcwd(NULL, 0);
        working_directory = current_directory == NULL ? NULL :
            tm_repo_relative_path(repository_root, current_directory);
        if (working_directory == NULL) {
            if (options.explain || signing_key != NULL)
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
            if (tm_command_fingerprint(&identity, command_fingerprint) == 0) {
                if (options.explain)
                    fprintf(stderr, "tm: command fingerprint: %s\n",
                            command_fingerprint);
            } else {
                if (options.explain || signing_key != NULL)
                    fprintf(stderr,
                        "tm: reuse rejected: command identity is not portable\n");
            }
        }
        free(current_directory);
        if (signing_key != NULL &&
            (working_directory == NULL || command_fingerprint[0] == '\0')) {
            free(working_directory);
            free_environment(child_environment);
            EVP_PKEY_free(signing_key);
            tm_profile_free(profile);
            tm_trust_policy_free(trust_policy);
            free(repository_root);
            return TM_EXIT_INTERNAL_ERROR;
        }
    }
    if (options.input_count > 0 || signing_key != NULL || profile != NULL) {
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
    if (!options.force && profile != NULL &&
        tm_profile_is_deterministic(profile) &&
        strcmp(tm_profile_privacy_class(profile), "public") == 0 &&
        options.output_count == 0 && options.input_count == 0 &&
        reusable_context && command_fingerprint[0] != '\0' &&
        repository_fd >= 0 && trust_policy != NULL && runtime_root != NULL) {
        char candidate_id[72];
        if (find_profile_cache_hit(repository_fd, profile, runtime_root,
                repository_root, command_fingerprint, context_fingerprint,
                trust_policy, candidate_id) == 0) {
            cache_hit = 1;
            result = 0;
            if (options.explain)
                fprintf(stderr, "tm: SKIP: trusted result %s\n", candidate_id);
        } else if (options.explain) {
            fprintf(stderr,
                "tm: RUN: no trusted result matched the stable input snapshot\n");
        }
    }
    if (!cache_hit) {
        int backend_result = 0;
        backend_used = profile != NULL && runtime_root != NULL ?
            tm_backend_run(profile, runtime_root, repository_root,
                options.output_paths, options.output_count,
                &argv[options.command_index], options.explain,
                &observer_report, &observed_inputs, &output_manifest,
                &backend_result) : 0;
        if (backend_used > 0) {
            result = backend_result;
        } else if (signing_key != NULL) {
            fprintf(stderr,
                "tm: trusted signing requires the controlled profile backend; command was not launched\n");
            result = TM_EXIT_INTERNAL_ERROR;
        } else {
            result = tm_observe_and_run(&argv[options.command_index],
                options.explain, child_environment, repository_root,
                &observer_report);
        }
    }
    if (options.explain && !cache_hit) {
        int observer_gate =
            tm_observer_report_allows_reuse(&observer_report);
        fprintf(stderr,
            "tm: observer eligibility: %s (coverage=%s, stable-view=%s, reasons=0x%08x; this alone cannot authorize reuse)\n",
            observer_gate ? "clear" : "blocked",
            observer_report.observation_complete ? "complete" : "incomplete",
            observer_report.stable_input_view ? "yes" : "no",
            observer_report.ineligibility_reasons);
    }
    if (options.explain && !cache_hit)
        for (index = 0; index < observer_report.candidate_count; index++) {
            const struct tm_observer_candidate *candidate =
                &observer_report.candidates[index];
            fprintf(stderr, "tm: observed input candidate: %s: %s\n",
                    candidate->kind,
                    candidate->external ? "<external>" : candidate->path);
        }
    for (index = 0; index < explicit_input_count; index++) {
        if (tm_input_matches(repository_fd, &explicit_inputs[index]) != 0) {
            explicit_inputs_unchanged = 0;
            if (options.explain)
                fprintf(stderr,
                        "tm: reuse rejected: declared input changed or became unsafe: %s\n",
                        explicit_inputs[index].path);
        }
    }
    if (!cache_hit && signing_key != NULL && result == 0 && !options.force &&
        tm_profile_is_deterministic(profile) &&
        strcmp(tm_profile_privacy_class(profile), "public") == 0 &&
        backend_used > 0 && reusable_context &&
        unavailable_input_count == 0 &&
        explicit_input_count == 0 && explicit_inputs_unchanged &&
        tm_observer_report_allows_reuse(&observer_report)) {
        struct tm_verification_identity identity = {
            tm_profile_repository_id(profile), command_fingerprint,
            working_directory, tm_profile_digest(profile),
            tm_profile_runtime_digest(profile), context_fingerprint,
            observed_inputs.items, observed_inputs.count
        };
        char verification_fingerprint[72];
        unsigned char *record = NULL;
        size_t record_length = 0;
        char record_id[72];
        if (tm_verification_fingerprint(&identity,
                                        verification_fingerprint) == 0 &&
            tm_result_create_with_outputs(&identity, signing_epoch,
                signing_key, &output_manifest,
                &record, &record_length, record_id) == 0 &&
            tm_result_store(repository_fd, record, record_length,
                            record_id) == 0) {
            if (options.explain)
                fprintf(stderr, "tm: signed result published: %s\n",
                        record_id);
        } else if (options.explain) {
            fprintf(stderr,
                "tm: successful command was not published (%s)\n",
                strerror(errno));
        }
        free(record);
    } else if (signing_key != NULL && options.explain && result == 0) {
        fprintf(stderr,
            "tm: successful command was not eligible for signed publication\n");
    }
    tm_observed_input_manifest_clear(&observed_inputs);
    tm_output_manifest_clear(&output_manifest);
    if (options.explain)
        for (index = 0; index < unavailable_input_count; index++)
            fprintf(stderr,
                    "tm: reuse rejected: declared input could not be captured: %s\n",
                    unavailable_inputs[index]);
    if (repository_fd >= 0) close(repository_fd);
    for (index = 0; index < explicit_input_count; index++)
        free(explicit_input_targets[index]);
    free_environment(child_environment);
    free(working_directory);
    EVP_PKEY_free(signing_key);
    free(repository_root);
    tm_profile_free(profile);
    tm_trust_policy_free(trust_policy);
    return result;
}
