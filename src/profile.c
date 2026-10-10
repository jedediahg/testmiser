#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/digest.h"
#include "tm/json.h"
#include "tm/profile.h"

#define PROFILE_LIMIT (1024U * 1024U)
#define PROFILE_ARRAY_LIMIT 4096U

struct tm_profile {
    struct tm_json_value *document;
    char *repository_id;
    char digest[72];
};

static const struct tm_json_value *get(const struct tm_json_value *value,
                                       const char *key)
{
    return tm_json_object_get(value, key);
}

static const char *string_value(const struct tm_json_value *value,
                                const char *key)
{
    return tm_json_string_value(get(value, key));
}

static int object_size(const struct tm_json_value *value, size_t size)
{
    return tm_json_typeof(value) == TM_JSON_OBJECT &&
           tm_json_size(value) == size;
}

static int valid_digest(const char *value)
{
    size_t i;
    if (value == NULL || strlen(value) != 71 || memcmp(value, "sha256:", 7))
        return 0;
    for (i = 7; i < 71; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return 1;
}

static int valid_repository_id(const char *value)
{
    size_t i, length;
    if (value == NULL || (length = strlen(value)) == 0 || length > 128 ||
        !((value[0] >= 'a' && value[0] <= 'z') ||
          (value[0] >= '0' && value[0] <= '9'))) return 0;
    for (i = 1; i < length; i++)
        if (!((value[i] >= 'a' && value[i] <= 'z') ||
              (value[i] >= '0' && value[i] <= '9') || value[i] == '.' ||
              value[i] == '_' || value[i] == '-')) return 0;
    return 1;
}

static int valid_relative_path(const char *path)
{
    const char *start;
    const char *p;
    if (path == NULL || path[0] == '\0' || path[0] == '/') return 0;
    start = path;
    for (p = path;; p++) {
        if (*p == '/' || *p == '\0') {
            size_t n = (size_t)(p - start);
            if (n == 0 || (n == 1 && start[0] == '.') ||
                (n == 2 && start[0] == '.' && start[1] == '.')) return 0;
            if (*p == '\0') return 1;
            start = p + 1;
        }
    }
}

static int valid_absolute_scratch(const char *path)
{
    const char *start;
    const char *p;
    if (path == NULL || path[0] != '/' || path[1] == '\0') return 0;
    start = path + 1;
    for (p = start;; p++) {
        if (*p == '/' || *p == '\0') {
            size_t n = (size_t)(p - start);
            if (n == 0 || (n == 1 && start[0] == '.') ||
                (n == 2 && start[0] == '.' && start[1] == '.')) return 0;
            if (*p == '\0') return 1;
            start = p + 1;
        }
    }
}

static int valid_sorted_paths(const struct tm_json_value *array,
                              int absolute)
{
    size_t i;
    const char *previous = NULL;
    if (tm_json_typeof(array) != TM_JSON_ARRAY ||
        tm_json_size(array) > PROFILE_ARRAY_LIMIT) return 0;
    for (i = 0; i < tm_json_size(array); i++) {
        const char *path = tm_json_string_value(tm_json_array_get(array, i));
        if (!(absolute ? valid_absolute_scratch(path) :
                         valid_relative_path(path)) ||
            (previous != NULL && strcmp(previous, path) >= 0)) return 0;
        previous = path;
    }
    return 1;
}

static int paths_overlap(const char *left, const char *right)
{
    size_t left_length = strlen(left), right_length = strlen(right);
    if (left_length == right_length && strcmp(left, right) == 0) return 1;
    if (left_length < right_length &&
        strncmp(left, right, left_length) == 0 && right[left_length] == '/')
        return 1;
    return right_length < left_length &&
           strncmp(right, left, right_length) == 0 && left[right_length] == '/';
}

static int disjoint_input_output_roots(const struct tm_json_value *inputs,
                                       const struct tm_json_value *outputs)
{
    size_t i, j;
    for (i = 0; i < tm_json_size(inputs); i++) {
        const char *input = tm_json_string_value(tm_json_array_get(inputs, i));
        for (j = 0; j < tm_json_size(outputs); j++) {
            const char *output = tm_json_string_value(
                tm_json_array_get(outputs, j));
            if (paths_overlap(input, output)) return 0;
        }
    }
    return 1;
}

static int valid_environment(const struct tm_json_value *environment)
{
    size_t i;
    if (tm_json_typeof(environment) != TM_JSON_OBJECT ||
        tm_json_size(environment) > PROFILE_ARRAY_LIMIT) return 0;
    for (i = 0; i < tm_json_size(environment); i++) {
        const char *name = tm_json_object_key_at(environment, i);
        size_t j;
        if (name == NULL || !((name[0] >= 'A' && name[0] <= 'Z') ||
                              (name[0] >= 'a' && name[0] <= 'z') ||
                              name[0] == '_') ||
            tm_json_typeof(tm_json_object_value_at(environment, i)) !=
                TM_JSON_STRING)
            return 0;
        for (j = 1; name[j] != '\0'; j++)
            if (!((name[j] >= 'A' && name[j] <= 'Z') ||
                  (name[j] >= 'a' && name[j] <= 'z') ||
                  (name[j] >= '0' && name[j] <= '9') || name[j] == '_'))
                return 0;
    }
    return 1;
}

static int read_file(const char *path, unsigned char **data, size_t *length)
{
    struct stat before, after;
    unsigned char *buffer;
    size_t used = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &before) < 0 || !S_ISREG(before.st_mode) ||
        before.st_size < 2 || (uint64_t)before.st_size > PROFILE_LIMIT) {
        close(fd); errno = EINVAL; return -1;
    }
    buffer = malloc((size_t)before.st_size);
    if (buffer == NULL) { close(fd); return -1; }
    while (used < (size_t)before.st_size) {
        ssize_t n = read(fd, buffer + used, (size_t)before.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(buffer); close(fd); errno = EIO; return -1; }
        used += (size_t)n;
    }
    if (fstat(fd, &after) < 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        free(buffer); close(fd); errno = EBUSY; return -1;
    }
    close(fd); *data = buffer; *length = used; return 0;
}

int tm_profile_load(const char *path, struct tm_profile **output)
{
    unsigned char *data = NULL;
    unsigned char *canonical = NULL;
    size_t length = 0, canonical_length = 0;
    struct tm_profile *profile = NULL;
    const char *repository_id;
    const char *backend;
    const char *workspace;
    const char *privacy;
    char hex[65];
    int result = -1;

    if (path == NULL || output == NULL) { errno = EINVAL; return -1; }
    *output = NULL;
    if (read_file(path, &data, &length) < 0) return -1;
    profile = calloc(1, sizeof(*profile));
    if (profile == NULL) goto done;
    if (tm_json_parse(data, length, &profile->document) < 0 ||
        !object_size(profile->document, 11)) goto invalid;
    repository_id = string_value(profile->document, "repository_id");
    backend = string_value(profile->document, "backend_contract");
    workspace = string_value(profile->document, "workspace_path");
    privacy = string_value(profile->document, "privacy_class");
    if (tm_json_integer_value(get(profile->document, "schema_version")) != 1 ||
        !valid_repository_id(repository_id) ||
        backend == NULL || strcmp(backend, "bubblewrap-linux-x86_64-v1") ||
        workspace == NULL || strcmp(workspace, "/workspace") ||
        !valid_digest(string_value(profile->document, "runtime_digest")) ||
        tm_json_typeof(get(profile->document, "deterministic")) !=
            TM_JSON_BOOLEAN ||
        (strcmp(privacy == NULL ? "" : privacy, "public") != 0 &&
         strcmp(privacy == NULL ? "" : privacy, "secret-dependent") != 0) ||
        !valid_environment(get(profile->document, "environment")) ||
        !valid_sorted_paths(get(profile->document, "input_roots"), 0) ||
        !valid_sorted_paths(get(profile->document, "output_roots"), 0) ||
        !valid_sorted_paths(get(profile->document, "scratch_roots"), 1) ||
        !disjoint_input_output_roots(get(profile->document, "input_roots"),
                                     get(profile->document, "output_roots")))
        goto invalid;
    if (tm_json_canonicalize(profile->document, &canonical,
                             &canonical_length) < 0 ||
        tm_sha256_bytes(canonical, canonical_length, hex) < 0) goto done;
    memcpy(profile->digest, "sha256:", 7);
    memcpy(profile->digest + 7, hex, sizeof(hex));
    profile->repository_id = strdup(repository_id);
    if (profile->repository_id == NULL) goto done;
    *output = profile;
    profile = NULL;
    result = 0;
    goto done;
invalid:
    errno = EBADMSG;
done:
    free(data);
    free(canonical);
    tm_profile_free(profile);
    return result;
}

void tm_profile_free(struct tm_profile *profile)
{
    if (profile == NULL) return;
    tm_json_free(profile->document);
    free(profile->repository_id);
    free(profile);
}

const char *tm_profile_repository_id(const struct tm_profile *profile)
{
    return profile == NULL ? NULL : profile->repository_id;
}

const char *tm_profile_digest(const struct tm_profile *profile)
{
    return profile == NULL ? NULL : profile->digest;
}
