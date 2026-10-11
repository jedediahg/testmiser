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
#include "tm/attempt.h"
#include "tm/clean.h"
#include "tm/context.h"
#include "tm/identity.h"
#include "tm/key.h"
#include "tm/lock.h"
#include "tm/local_store.h"
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

extern char **environ;

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

static int is_supervisor_environment_entry(const char *entry)
{
    static const char *const names[] = {
        "TM_SHARED_STORE", "TM_RUNTIME_ROOT", "TM_COORDINATION_MODE",
        "TM_FORCE"
    };
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
        size_t length = strlen(names[index]);
        if (strncmp(entry, names[index], length) == 0 && entry[length] == '=')
            return 1;
    }
    return 0;
}

static char **inherited_child_environment(void)
{
    size_t count = 0, output = 0, index;
    char **environment;
    while (environ != NULL && environ[count] != NULL) count++;
    environment = calloc(count + 1, sizeof(*environment));
    if (environment == NULL) return NULL;
    for (index = 0; index < count; index++) {
        if (is_supervisor_environment_entry(environ[index])) continue;
        environment[output] = strdup(environ[index]);
        if (environment[output] == NULL) {
            while (output > 0) free(environment[--output]);
            free(environment);
            return NULL;
        }
        output++;
    }
    return environment;
}

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
        char *entry = malloc(length);
        if (entry == NULL) {
            free_environment(environment);
            return NULL;
        }
        environment[index] = entry;
        (void)snprintf(entry, length, "%s=%s", name, value);
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
            {
                char *entry = malloc(length);
                if (entry == NULL) {
                    free_environment(environment);
                    return NULL;
                }
                environment[index] = entry;
                (void)snprintf(entry, length, "%s=%s", name, value);
            }
            index++;
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

static int output_manifests_equal(const struct tm_output_manifest *left,
                                  const struct tm_output_manifest *right)
{
    size_t index;
    if (left->count != right->count) return 0;
    for (index = 0; index < left->count; index++) {
        const struct tm_output_entry *a = &left->entries[index];
        const struct tm_output_entry *b = &right->entries[index];
        if (strcmp(a->path, b->path) != 0 || a->kind != b->kind ||
            a->mode != b->mode || strcmp(a->digest, b->digest) != 0 ||
            a->size != b->size) return 0;
    }
    return 1;
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
    fprintf(stream, "       tm attempt resolve --repository-id ID --command-fingerprint SHA256\n");
    fprintf(stream, "                         --profile-digest SHA256 --context-digest SHA256\n");
    fprintf(stream, "                         (--fingerprint SHA256 | --all)\n");
    fprintf(stream, "Run a verification command; reuse requires an approved, completely observed profile.\n");
    fprintf(stream, "Options:\n");
    fprintf(stream, "  --force    always run the command\n");
    fprintf(stream, "  TM_FORCE=1 has the same effect as --force\n");
    fprintf(stream, "  --explain  explain RUN/SKIP and the evidence decision\n");
    fprintf(stream, "  --profile FILE       select an approved profile for controlled reuse\n");
    fprintf(stream, "  --trust-policy FILE  load operator trust configuration\n");
    fprintf(stream, "  --signing-key FILE   sign eligible controlled-profile successes\n");
    fprintf(stream, "  --root DIR           set repository root (default: nearest .git)\n");
    fprintf(stream, "  --input PATH         declare a repository-relative input file\n");
    fprintf(stream, "  --output PATH        declare a repository-relative output root\n");
    fprintf(stream, "  TM_COORDINATION_MODE=available|strict (strict requires TM_SHARED_STORE)\n");
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

static int attempt_command(int argc, char **argv)
{
    const char *repository_id = NULL, *command = NULL, *profile = NULL;
    const char *context = NULL, *fingerprint = NULL;
    int resolve_all = 0, index;
    struct tm_attempt_state state = {.directory_fd = -1};
    if (argc < 3 || strcmp(argv[2], "resolve") != 0) goto usage;
    for (index = 3; index < argc;) {
        const char *option = argv[index];
        const char **destination = NULL;
        if (strcmp(option, "--all") == 0) {
            if (resolve_all || fingerprint != NULL) goto usage;
            resolve_all = 1;
            index++;
            continue;
        }
        if (strcmp(option, "--repository-id") == 0) destination = &repository_id;
        else if (strcmp(option, "--command-fingerprint") == 0) destination = &command;
        else if (strcmp(option, "--profile-digest") == 0) destination = &profile;
        else if (strcmp(option, "--context-digest") == 0) destination = &context;
        else if (strcmp(option, "--fingerprint") == 0) destination = &fingerprint;
        else goto usage;
        if (index + 1 >= argc || *destination != NULL || resolve_all ||
            argv[index + 1][0] == '\0') goto usage;
        *destination = argv[index + 1];
        index += 2;
    }
    if (repository_id == NULL || command == NULL || profile == NULL ||
        context == NULL || (fingerprint == NULL && !resolve_all)) goto usage;
    if (tm_attempt_state_open_default(repository_id, command, profile,
                                      context, &state) < 0) {
        fprintf(stderr, "tm: cannot open local attempt state: %s\n",
                strerror(errno));
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (tm_attempt_state_resolve(&state, resolve_all ? NULL : fingerprint) < 0) {
        fprintf(stderr, "tm: cannot resolve local attempt state: %s\n",
                strerror(errno));
        tm_attempt_state_clear(&state);
        return TM_EXIT_INTERNAL_ERROR;
    }
    printf("tm: local attempt state resolved for %s\n",
           resolve_all ? "all fingerprints in this command/context" :
                         fingerprint);
    tm_attempt_state_clear(&state);
    return 0;
usage:
    fprintf(stderr,
        "Usage: tm attempt resolve --repository-id ID --command-fingerprint SHA256 --profile-digest SHA256 --context-digest SHA256 (--fingerprint SHA256 | --all)\n");
    return TM_EXIT_INTERNAL_ERROR;
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
                                  const char *const *output_roots,
                                  size_t output_root_count,
                                  const char *const *blocked_fingerprints,
                                  size_t blocked_count,
                                  int probe_only,
                                  char verification_fingerprint[72],
                                  const char **found_source,
                                  char record_id[72])
{
    struct tm_snapshot *snapshot = NULL;
    const char **root_paths = NULL;
    int *root_descriptors = NULL;
    unsigned char *record = NULL;
    size_t record_length = 0, root_count, index;
    int preflight, found = 1, shared_store_fd = -1;
    int configured_store_fd = -1;
    if (found_source != NULL) *found_source = "repository";
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
    if (probe_only)
        found = tm_result_find_matching_snapshot_record(repository_fd,
            command_fingerprint, tm_profile_digest(profile),
            tm_profile_runtime_digest(profile), context_fingerprint,
            trust_policy, root_paths, root_descriptors, root_count,
            &record, &record_length, record_id);
    else
        found = tm_result_find_matching_snapshot_inputs_and_restore_blocked(
            repository_fd, repository_fd, repository_fd, command_fingerprint,
            tm_profile_digest(profile), tm_profile_runtime_digest(profile),
            context_fingerprint, trust_policy, root_paths, root_descriptors,
            root_count, output_roots, output_root_count, blocked_fingerprints,
            blocked_count, &record, &record_length, record_id);
    if (found != 0 && tm_local_store_open_default(&shared_store_fd) == 0) {
        free(record); record = NULL; record_length = 0;
        if (probe_only)
            found = tm_result_find_matching_snapshot_record(shared_store_fd,
                command_fingerprint, tm_profile_digest(profile),
                tm_profile_runtime_digest(profile), context_fingerprint,
                trust_policy, root_paths, root_descriptors, root_count,
                &record, &record_length, record_id);
        else
            found = tm_result_find_matching_snapshot_inputs_and_restore_blocked(
                shared_store_fd, repository_fd, shared_store_fd,
                command_fingerprint, tm_profile_digest(profile),
                tm_profile_runtime_digest(profile), context_fingerprint,
                trust_policy, root_paths, root_descriptors, root_count,
                output_roots, output_root_count, blocked_fingerprints,
                blocked_count, &record, &record_length, record_id);
        if (found == 0 && found_source != NULL)
            *found_source = "per-user shared store";
    }
    if (found != 0 &&
        tm_shared_store_open_configured(&configured_store_fd) == 0) {
        free(record); record = NULL; record_length = 0;
        if (probe_only)
            found = tm_result_find_matching_snapshot_record(configured_store_fd,
                command_fingerprint, tm_profile_digest(profile),
                tm_profile_runtime_digest(profile), context_fingerprint,
                trust_policy, root_paths, root_descriptors, root_count,
                &record, &record_length, record_id);
        else
            found = tm_result_find_matching_snapshot_inputs_and_restore_blocked(
                configured_store_fd, repository_fd, configured_store_fd,
                command_fingerprint, tm_profile_digest(profile),
                tm_profile_runtime_digest(profile), context_fingerprint,
                trust_policy, root_paths, root_descriptors, root_count,
                output_roots, output_root_count, blocked_fingerprints,
                blocked_count, &record, &record_length, record_id);
        if (found == 0 && found_source != NULL)
            *found_source = "configured shared store";
    } else if (found != 0 && getenv("TM_SHARED_STORE") != NULL &&
               getenv("TM_SHARED_STORE")[0] != '\0') {
        fprintf(stderr, "tm: configured shared result store is unavailable (%s)\n",
                strerror(errno));
    }
    if (found == 0 && verification_fingerprint != NULL) {
        struct tm_result_summary summary = {0};
        char inspected_id[72];
        if (tm_result_inspect(record, record_length, &summary, inspected_id) < 0)
            found = -1;
        else {
            memcpy(verification_fingerprint, summary.verification_fingerprint,
                   72);
            tm_result_summary_clear(&summary);
        }
    }
    if (found == 0) found = 0;
    else found = 1;
done:
    if (root_descriptors != NULL)
        for (index = 0; index < root_count; index++)
            if (root_descriptors[index] >= 0) close(root_descriptors[index]);
    free(record);
    if (shared_store_fd >= 0) close(shared_store_fd);
    if (configured_store_fd >= 0) close(configured_store_fd);
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
    struct tm_lock invocation_lock = {-1};
    struct tm_attempt_state attempt_state = {.directory_fd = -1};
    EVP_PKEY *signing_key = NULL;
    char **child_environment = NULL;
    const char *force_environment;
    const char *runtime_root = NULL;
    char *repository_root = NULL;
    char *working_directory = NULL;
    char command_fingerprint[72] = {0};
    char context_fingerprint[72] = {0};
    char prior_forced_fingerprint[72] = {0};
    int prior_forced_success = 0;
    const char *prior_forced_source = NULL;
    char signing_key_id[72] = {0};
    uint64_t signing_epoch = 0;
    struct tm_input_observation explicit_inputs[TM_MAX_EXPLICIT_INPUTS];
    char explicit_input_digests[TM_MAX_EXPLICIT_INPUTS][72];
    char *explicit_input_targets[TM_MAX_EXPLICIT_INPUTS] = {0};
    const char *unavailable_inputs[TM_MAX_EXPLICIT_INPUTS];
    size_t explicit_input_count = 0, unavailable_input_count = 0, index;
    int repository_fd = -1;
    int lock_store_fd = -1;
    int backend_used = 0;
    int reusable_context = 0;
    int lock_eligible_profile = 0;
    int explicit_inputs_unchanged = 1;
    int cache_hit = 0;
    int invocation_lock_acquired = 0;
    int strict_coordination = 0;
    int attempt_state_ready = 0, attempt_started = 0;
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
    if (argc > 1 && strcmp(argv[1], "attempt") == 0)
        return attempt_command(argc, argv);
    parse_result = parse_options(argc, argv, &options);
    if (parse_result != 0) {
        return parse_result > 0 ? 0 : TM_EXIT_INTERNAL_ERROR;
    }
    force_environment = getenv("TM_FORCE");
    if (force_environment != NULL && strcmp(force_environment, "1") == 0)
        options.force = 1;
    {
        const char *coordination_mode = getenv("TM_COORDINATION_MODE");
        if (coordination_mode != NULL && coordination_mode[0] != '\0') {
            if (strcmp(coordination_mode, "available") == 0) {
                strict_coordination = 0;
            } else if (strcmp(coordination_mode, "strict") == 0) {
                strict_coordination = 1;
                if (getenv("TM_SHARED_STORE") == NULL ||
                    getenv("TM_SHARED_STORE")[0] == '\0') {
                    fprintf(stderr,
                        "tm: strict coordination requires TM_SHARED_STORE\n");
                    return TM_EXIT_INTERNAL_ERROR;
                }
            } else {
                fprintf(stderr,
                    "tm: TM_COORDINATION_MODE must be 'available' or 'strict'\n");
                return TM_EXIT_INTERNAL_ERROR;
            }
        }
    }

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
        lock_eligible_profile = tm_profile_is_deterministic(profile) &&
            strcmp(tm_profile_privacy_class(profile), "public") == 0;
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
            fprintf(stderr, "tm: RUN: profile approved; reuse still requires a trusted matching result and complete observation\n");
        }
        child_environment = profile_environment(profile);
        if (child_environment == NULL) {
            fprintf(stderr, "tm: cannot construct profile environment\n");
            tm_profile_free(profile);
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (options.explain || signing_key != NULL || !options.force ||
            lock_eligible_profile) {
            struct tm_json_value *environment =
                environment_json(child_environment);
            struct tm_json_value *execution_context = NULL;
            struct tm_json_value *profile_context = NULL;
            char *bubblewrap_path = NULL;
            char bubblewrap_digest[72];
            const char *fingerprint_failure = NULL;
            int fingerprint_errno = 0;
            if (environment == NULL) {
                fingerprint_failure = "profile environment";
                fingerprint_errno = errno;
            } else if (tm_backend_executable_identity(&bubblewrap_path,
                                                       bubblewrap_digest) < 0) {
                fingerprint_failure = "Bubblewrap identity";
                fingerprint_errno = errno;
            } else if (tm_context_capture_linux(&execution_context) < 0) {
                fingerprint_failure = "Linux host context";
                fingerprint_errno = errno;
            } else if (tm_context_project_bubblewrap(execution_context,
                    tm_profile_backend_contract(profile), bubblewrap_digest,
                    &profile_context) < 0) {
                fingerprint_failure = "Bubblewrap context projection";
                fingerprint_errno = errno;
            } else if (tm_context_fingerprint(environment, profile_context,
                                               context_fingerprint) < 0) {
                fingerprint_failure = "profile context fingerprint";
                fingerprint_errno = errno;
            }
            if (fingerprint_failure != NULL) {
                if (options.explain || signing_key != NULL)
                    fprintf(stderr,
                        "tm: reuse rejected: %s could not be fingerprinted (%s)\n",
                        fingerprint_failure, strerror(fingerprint_errno));
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
                    fprintf(stderr, "tm: context fingerprint: %s (one reuse eligibility input)\n",
                            context_fingerprint);
            }
            free(bubblewrap_path);
            tm_json_free(profile_context);
            tm_json_free(execution_context);
            tm_json_free(environment);
        }
    } else {
        child_environment = inherited_child_environment();
        if (child_environment == NULL) {
            fprintf(stderr, "tm: cannot construct child environment\n");
            tm_trust_policy_free(trust_policy);
            return TM_EXIT_INTERNAL_ERROR;
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
    if ((options.explain || signing_key != NULL || !options.force ||
         lock_eligible_profile) &&
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
    if (profile != NULL &&
        tm_profile_is_deterministic(profile) &&
        strcmp(tm_profile_privacy_class(profile), "public") == 0 &&
        reusable_context && command_fingerprint[0] != '\0' &&
        repository_fd >= 0 && trust_policy != NULL && runtime_root != NULL) {
        if (tm_shared_store_open_configured(&lock_store_fd) == 0) {
            int lock_result = options.explain ?
                tm_lock_try_acquire_store(lock_store_fd,
                    tm_profile_repository_id(profile), command_fingerprint,
                    tm_profile_digest(profile), context_fingerprint,
                    &invocation_lock) : -1;
            if (lock_result == 1) {
                fprintf(stderr, "tm: WAIT: equivalent invocation owns the shared execution slot; waiting to recheck trusted results\n");
                lock_result = tm_lock_acquire_store(lock_store_fd,
                    tm_profile_repository_id(profile), command_fingerprint,
                    tm_profile_digest(profile), context_fingerprint,
                    &invocation_lock);
            } else if (lock_result < 0) {
                lock_result = tm_lock_acquire_store(lock_store_fd,
                    tm_profile_repository_id(profile), command_fingerprint,
                    tm_profile_digest(profile), context_fingerprint,
                    &invocation_lock);
            }
            if (lock_result == 0) {
                invocation_lock_acquired = 1;
            } else if (strict_coordination) {
                fprintf(stderr,
                    "tm: strict coordination could not acquire the shared execution slot (%s)\n",
                    strerror(errno));
            } else if (options.explain) {
                fprintf(stderr, "tm: shared-store invocation lock unavailable; concurrent cold runs may duplicate work\n");
            }
            close(lock_store_fd);
            lock_store_fd = -1;
        } else if (strict_coordination) {
            fprintf(stderr,
                "tm: strict coordination could not open TM_SHARED_STORE (%s)\n",
                strerror(errno));
        } else if (options.explain) {
            fprintf(stderr,
                "tm: shared-store invocation lock unavailable; concurrent cold runs may duplicate work (%s)\n",
                strerror(errno));
        }
        if (!strict_coordination && !invocation_lock_acquired) {
            int lock_result = -1;
            if (options.explain) {
                lock_result = tm_lock_try_acquire_default(
                    tm_profile_repository_id(profile), command_fingerprint,
                    tm_profile_digest(profile), context_fingerprint,
                    &invocation_lock);
                if (lock_result == 1)
                    fprintf(stderr, "tm: WAIT: equivalent invocation owns the per-user execution slot; waiting to recheck trusted results\n");
            }
            if (lock_result != 0)
                lock_result = tm_lock_acquire_default(
                    tm_profile_repository_id(profile), command_fingerprint,
                    tm_profile_digest(profile), context_fingerprint,
                    &invocation_lock);
            if (lock_result == 0) invocation_lock_acquired = 1;
            if (!invocation_lock_acquired && options.explain)
                fprintf(stderr, "tm: invocation lock unavailable; concurrent cold runs may duplicate work\n");
        }
    }
    if (invocation_lock_acquired) {
        struct tm_json_value *environment = environment_json(child_environment);
        struct tm_json_value *execution_context = NULL;
        struct tm_json_value *profile_context = NULL;
        char *bubblewrap_path = NULL;
        char bubblewrap_digest[72], current_context[72];
        int stable = environment != NULL &&
            tm_backend_executable_identity(&bubblewrap_path,
                bubblewrap_digest) == 0 &&
            tm_context_capture_linux(&execution_context) == 0 &&
            tm_context_project_bubblewrap(execution_context,
                tm_profile_backend_contract(profile), bubblewrap_digest,
                &profile_context) == 0 &&
            tm_context_fingerprint(environment, profile_context,
                current_context) == 0 &&
            strcmp(current_context, context_fingerprint) == 0;
        free(bubblewrap_path);
        tm_json_free(profile_context);
        tm_json_free(execution_context);
        tm_json_free(environment);
        if (!stable) {
            reusable_context = 0;
            tm_lock_release(&invocation_lock);
            invocation_lock_acquired = 0;
            if (options.explain)
                fprintf(stderr, "tm: reuse rejected: execution context changed while waiting for the invocation lock\n");
        }
    }
    if (strict_coordination && !invocation_lock_acquired) {
        fprintf(stderr,
            "tm: strict coordination unavailable; command was not launched\n");
        result = TM_EXIT_INTERNAL_ERROR;
        goto cleanup;
    }
    if (invocation_lock_acquired && profile != NULL &&
        tm_profile_is_deterministic(profile) &&
        strcmp(tm_profile_privacy_class(profile), "public") == 0 &&
        reusable_context && command_fingerprint[0] != '\0' &&
        trust_policy != NULL && runtime_root != NULL) {
        if (tm_attempt_state_open_default(tm_profile_repository_id(profile),
                command_fingerprint, tm_profile_digest(profile),
                context_fingerprint, &attempt_state) == 0) {
            attempt_state_ready = 1;
            if (attempt_state.stale_running && options.explain)
                fprintf(stderr, "tm: prior interrupted attempt blocks reuse until an eligible success\n");
        } else if (options.explain) {
            fprintf(stderr, "tm: local attempt state unavailable; cache reuse is disabled (%s)\n",
                    strerror(errno));
        }
    }
    if (options.force && options.explain)
        fprintf(stderr, "tm: force requested; command will execute\n");
    if (attempt_state_ready && attempt_state.blocked_all && options.explain)
        fprintf(stderr, "tm: RUN: local incomplete or interrupted attempt blocks reuse for this command/context\n");
    if (options.force && attempt_state_ready &&
        profile != NULL && command_fingerprint[0] != '\0') {
        char prior_record_id[72];
        if (find_profile_cache_hit(repository_fd, profile, runtime_root,
                repository_root, command_fingerprint, context_fingerprint,
                trust_policy, options.output_paths, options.output_count,
                NULL, 0, 1, prior_forced_fingerprint,
                &prior_forced_source,
                prior_record_id) == 0) {
            prior_forced_success = 1;
            if (options.explain)
                fprintf(stderr, "tm: forced run is checking trusted prior result %s (source=%s)\n",
                        prior_record_id, prior_forced_source);
        }
    }
    if (options.explain && options.output_count > 0 && profile == NULL)
        fprintf(stderr, "tm: reuse rejected: --output requires an approved enforced profile\n");
    if (!options.force && attempt_state_ready &&
        !attempt_state.blocked_all && profile != NULL &&
        tm_profile_is_deterministic(profile) &&
        strcmp(tm_profile_privacy_class(profile), "public") == 0 &&
        reusable_context && command_fingerprint[0] != '\0' &&
        repository_fd >= 0 && trust_policy != NULL && runtime_root != NULL) {
        char candidate_id[72];
        char candidate_verification_fingerprint[72];
        const char *candidate_source = NULL;
        if (find_profile_cache_hit(repository_fd, profile, runtime_root,
                repository_root, command_fingerprint, context_fingerprint,
                trust_policy, options.output_paths, options.output_count,
                (const char *const *)attempt_state.blocked_fingerprints,
                attempt_state.blocked_count,
                0, candidate_verification_fingerprint,
                &candidate_source,
                candidate_id) == 0) {
            cache_hit = 1;
            result = 0;
            if (options.explain)
                fprintf(stderr,
                    "tm: SKIP: trusted result record=%s verification=%s source=%s\n",
                    candidate_id, candidate_verification_fingerprint,
                    candidate_source);
        } else if (options.explain) {
            fprintf(stderr,
                "tm: RUN: no trusted result matched the stable input snapshot\n");
        }
    }
    if (!cache_hit) {
        int backend_result = 0;
        if (attempt_state_ready && tm_attempt_state_begin(&attempt_state) == 0)
            attempt_started = 1;
        else if (attempt_state_ready) {
            attempt_state_ready = 0;
            if (options.explain)
                fprintf(stderr, "tm: could not persist pending attempt; this run will not publish or reuse local evidence\n");
        }
        backend_used = profile != NULL && runtime_root != NULL ?
            tm_backend_run(profile, runtime_root, repository_root,
                options.input_paths, options.input_count,
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
        unavailable_input_count == 0 && explicit_inputs_unchanged &&
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
        int shared_store_fd = -1;
        int configured_store_fd = -1;
        int record_ready = 0, published_anywhere = 0;
        struct tm_output_manifest shared_outputs = {0};
        struct tm_lock repository_results_lock = {-1};
        if (tm_verification_fingerprint(&identity,
                                        verification_fingerprint) == 0 &&
            tm_result_create_with_outputs(&identity, signing_epoch,
                signing_key, &output_manifest,
                &record, &record_length, record_id) == 0)
            record_ready = 1;
        if (record_ready) {
            if (tm_lock_acquire_repository_results(repository_fd,
                    &repository_results_lock) == 0) {
                if (tm_result_store(repository_fd, record, record_length,
                                    record_id) == 0) {
                    published_anywhere = 1;
                    if (options.explain)
                        fprintf(stderr, "tm: signed result published: %s\n",
                                record_id);
                } else if (options.explain) {
                    fprintf(stderr,
                        "tm: repository result publication failed (%s)\n",
                        strerror(errno));
                }
                tm_lock_release(&repository_results_lock);
            } else if (options.explain) {
                fprintf(stderr,
                    "tm: repository publication lock unavailable (%s)\n",
                    strerror(errno));
            }
            if (tm_local_store_open_default(&shared_store_fd) == 0) {
                int blobs_ready = options.output_count == 0 ||
                    (tm_outputs_capture_to_store(repository_fd,
                        shared_store_fd, options.output_paths,
                        options.output_count, &shared_outputs) == 0 &&
                     output_manifests_equal(&output_manifest,
                                            &shared_outputs));
                if (blobs_ready &&
                    tm_result_store(shared_store_fd, record, record_length,
                                    record_id) == 0) {
                    published_anywhere = 1;
                    if (options.explain)
                        fprintf(stderr, "tm: signed result published to the per-user shared store\n");
                } else if (options.explain) {
                    fprintf(stderr,
                        "tm: per-user shared-store publication failed or outputs changed (%s)\n",
                        strerror(errno));
                }
            } else if (options.explain) {
                fprintf(stderr,
                    "tm: per-user shared store is unavailable (%s)\n",
                    strerror(errno));
            }
            if (tm_shared_store_open_configured(&configured_store_fd) == 0) {
                int blobs_ready = options.output_count == 0 ||
                    (tm_outputs_capture_to_store(repository_fd,
                        configured_store_fd, options.output_paths,
                        options.output_count, &shared_outputs) == 0 &&
                     output_manifests_equal(&output_manifest,
                                            &shared_outputs));
                if (blobs_ready &&
                    tm_result_store(configured_store_fd, record, record_length,
                                    record_id) == 0) {
                    published_anywhere = 1;
                    if (options.explain)
                        fprintf(stderr, "tm: signed result published to configured shared store\n");
                } else if (options.explain) {
                    fprintf(stderr,
                        "tm: shared-store publication failed or outputs changed (%s)\n",
                        strerror(errno));
                }
                tm_output_manifest_clear(&shared_outputs);
            } else if (getenv("TM_SHARED_STORE") != NULL &&
                       getenv("TM_SHARED_STORE")[0] != '\0' && options.explain) {
                fprintf(stderr, "tm: configured shared result store is unavailable (%s)\n",
                        strerror(errno));
            }
            if (!published_anywhere && options.explain)
                fprintf(stderr,
                    "tm: signed result could not be published to any store\n");
        } else if (options.explain) {
            fprintf(stderr,
                "tm: successful command could not be signed (%s)\n",
                strerror(errno));
        }
        tm_output_manifest_clear(&shared_outputs);
        if (shared_store_fd >= 0) close(shared_store_fd);
        if (configured_store_fd >= 0) close(configured_store_fd);
        free(record);
    } else if (signing_key != NULL && options.explain && result == 0) {
        fprintf(stderr,
            "tm: successful command was not eligible for signed publication\n");
    }
    if (attempt_started) {
        const char *verification_fingerprint = NULL;
        char computed_fingerprint[72];
        int exact = backend_used > 0 && reusable_context &&
            unavailable_input_count == 0 && explicit_inputs_unchanged &&
            tm_observer_report_allows_reuse(&observer_report);
        if (exact) {
            struct tm_verification_identity identity = {
                tm_profile_repository_id(profile), command_fingerprint,
                working_directory, tm_profile_digest(profile),
                tm_profile_runtime_digest(profile), context_fingerprint,
                observed_inputs.items, observed_inputs.count
            };
            if (tm_verification_fingerprint(&identity, computed_fingerprint) == 0)
                verification_fingerprint = computed_fingerprint;
        }
        if (result == 0 && verification_fingerprint != NULL) {
            if (tm_attempt_state_finish(&attempt_state,
                    TM_ATTEMPT_ELIGIBLE_SUCCESS,
                    verification_fingerprint) < 0 && options.explain)
                fprintf(stderr, "tm: could not resolve local attempt state: %s\n",
                        strerror(errno));
        } else if (result != 0) {
            int contradictory = options.force && prior_forced_success &&
                verification_fingerprint != NULL &&
                strcmp(prior_forced_fingerprint,
                       verification_fingerprint) == 0;
            enum tm_attempt_outcome outcome = contradictory ?
                TM_ATTEMPT_QUARANTINED : TM_ATTEMPT_FAILED;
            if (tm_attempt_state_finish(&attempt_state, outcome,
                    verification_fingerprint) < 0 && options.explain)
                fprintf(stderr, "tm: could not persist failed attempt state: %s\n",
                        strerror(errno));
            else if (contradictory && options.explain)
                fprintf(stderr, "tm: CONTRADICTION: forced failure matches trusted prior success; fingerprint quarantined\n");
        } else {
            (void)tm_attempt_state_finish(&attempt_state, TM_ATTEMPT_RUN_ONLY,
                                          NULL);
        }
    }
cleanup:
    tm_observed_input_manifest_clear(&observed_inputs);
    tm_output_manifest_clear(&output_manifest);
    tm_attempt_state_clear(&attempt_state);
    if (invocation_lock_acquired) tm_lock_release(&invocation_lock);
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
