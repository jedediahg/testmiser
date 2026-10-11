#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "tm/input.h"
#include "tm/observed_inputs.h"

static void free_fields(struct tm_observed_input_manifest *manifest)
{
    size_t index;
    for (index = 0; index < manifest->owned_field_count; index++)
        free(manifest->owned_fields[index]);
    free(manifest->owned_fields);
    free(manifest->items);
    memset(manifest, 0, sizeof(*manifest));
}

void tm_observed_input_manifest_clear(
    struct tm_observed_input_manifest *manifest)
{
    if (manifest != NULL) free_fields(manifest);
}

static int own_field(struct tm_observed_input_manifest *manifest,
                     const char *value, const char **owned)
{
    char *copy;
    if (manifest->owned_field_count >= manifest->owned_field_capacity) {
        errno = EOVERFLOW;
        return -1;
    }
    copy = strdup(value);
    if (copy == NULL) return -1;
    manifest->owned_fields[manifest->owned_field_count++] = copy;
    *owned = copy;
    return 0;
}

static int compare_inputs(const void *left, const void *right)
{
    const struct tm_input_observation *a = left;
    const struct tm_input_observation *b = right;
    int result = strcmp(a->path, b->path);
    if (result != 0) return result;
    return (int)a->kind - (int)b->kind;
}

static int input_equal(const struct tm_input_observation *left,
                       const struct tm_input_observation *right)
{
    if (left->kind != right->kind) return 0;
    switch (left->kind) {
    case TM_INPUT_FILE:
    case TM_INPUT_DIRECTORY:
        return left->digest != NULL && right->digest != NULL &&
               strcmp(left->digest, right->digest) == 0;
    case TM_INPUT_EXISTS:
        return left->exists == right->exists;
    case TM_INPUT_SYMLINK:
        return left->target != NULL && right->target != NULL &&
               strcmp(left->target, right->target) == 0;
    }
    return 0;
}

static int classify_candidate(const struct tm_observer_candidate *candidate,
                              enum tm_input_kind *kind)
{
    if (strcmp(candidate->kind, "opened file") == 0 ||
        strcmp(candidate->kind, "read descriptor") == 0 ||
        strcmp(candidate->kind, "mapped file") == 0 ||
        strcmp(candidate->kind, "executable") == 0) {
        *kind = TM_INPUT_FILE;
        return 0;
    }
    if (strcmp(candidate->kind, "opened directory") == 0 ||
        strcmp(candidate->kind, "directory listing") == 0 ||
        strcmp(candidate->kind, "cwd change") == 0) {
        *kind = TM_INPUT_DIRECTORY;
        return 0;
    }
    if (strcmp(candidate->kind, "absent path") == 0 ||
        strcmp(candidate->kind, "absent executable") == 0) {
        *kind = TM_INPUT_EXISTS;
        return 0;
    }
    if (strcmp(candidate->kind, "symlink") == 0) {
        *kind = TM_INPUT_SYMLINK;
        return 0;
    }
    errno = ENOTSUP;
    return -1;
}

static int path_is_canonical(const char *path);

static int join_relative(const char *parent, const char *child,
                         char *output, size_t capacity)
{
    size_t parent_length, child_length;
    int length;
    if (parent == NULL || child == NULL || output == NULL || capacity == 0) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(parent, ".") == 0 || parent[0] == '\0') parent_length = 0;
    else parent_length = strlen(parent);
    if (strcmp(child, ".") == 0 || child[0] == '\0') {
        if (parent_length == 0) {
            if (snprintf(output, capacity, ".") >= (int)capacity) goto too_long;
        } else if (snprintf(output, capacity, "%s", parent) >= (int)capacity) {
            goto too_long;
        }
        return 0;
    }
    child_length = strlen(child);
    length = snprintf(output, capacity, "%s%s%s",
        parent_length == 0 ? "" : parent,
        parent_length == 0 ? "" : "/", child);
    if (length < 0 || (size_t)length >= capacity ||
        child_length >= capacity) goto too_long;
    return 0;
too_long:
    errno = ENAMETOOLONG;
    return -1;
}

static int append_observation(struct tm_observed_input_manifest *manifest,
                              int root_fd, enum tm_input_kind kind,
                              const char *logical_path,
                              const char *source_path,
                              const char *known_target)
{
    struct tm_input_observation *observation;
    size_t index;
    char digest[72];
    char *target = NULL;
    int exists = 1;

    if (kind == TM_INPUT_FILE) {
        int captured = strcmp(source_path, ".") == 0 ?
            tm_input_capture_file_root(root_fd, digest) :
            tm_input_capture_file(root_fd, source_path, digest);
        if (captured < 0)
            return -1;
    } else if (kind == TM_INPUT_DIRECTORY) {
        int captured = strcmp(source_path, ".") == 0 ?
            tm_input_capture_directory_root(root_fd, digest) :
            tm_input_capture_directory(root_fd, source_path, digest);
        if (captured < 0)
            return -1;
    } else if (kind == TM_INPUT_EXISTS) {
        if (tm_input_capture_exists(root_fd, source_path, &exists) < 0 ||
            exists) {
            if (exists) errno = ESTALE;
            return -1;
        }
    } else {
        if (known_target != NULL) target = strdup(known_target);
        else if (tm_input_capture_symlink(root_fd, source_path,
                                          &target) < 0) return -1;
        if (target == NULL) return -1;
    }

    for (index = 0; index < manifest->count; index++) {
        observation = &manifest->items[index];
        if (strcmp(observation->path, logical_path) != 0) continue;
        {
            struct tm_input_observation current = {(char *)logical_path, kind,
                kind == TM_INPUT_FILE || kind == TM_INPUT_DIRECTORY ?
                    digest : NULL,
                target, kind == TM_INPUT_EXISTS ? exists : 0};
            int equal = input_equal(observation, &current);
            free(target);
            if (equal) return 0;
            errno = ESTALE;
            return -1;
        }
    }

    if (manifest->count >= manifest->capacity) {
        free(target);
        errno = EOVERFLOW;
        return -1;
    }
    observation = &manifest->items[manifest->count];
    memset(observation, 0, sizeof(*observation));
    if (own_field(manifest, logical_path, &observation->path) < 0) {
        free(target);
        return -1;
    }
    observation->kind = kind;
    observation->exists = 0;
    if (kind == TM_INPUT_FILE || kind == TM_INPUT_DIRECTORY) {
        if (own_field(manifest, digest, &observation->digest) < 0) {
            free(target);
            return -1;
        }
    } else if (kind == TM_INPUT_SYMLINK) {
        observation->target = target;
        manifest->owned_fields[manifest->owned_field_count++] = target;
    }
    manifest->count++;
    return 0;
}

static int make_logical_path(const char *root_path, const char *relative_path,
                             char output[4096])
{
    if (join_relative(root_path, relative_path, output, 4096) < 0)
        return -1;
    if (!path_is_canonical(output) && strcmp(output, ".") != 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Resolve symlink components against the pinned root. Every link is captured
 * before following it, and the final file/directory observation uses its
 * resolved root-relative path. Parent components are therefore link-free
 * when the manifest is later rechecked. */
static int resolve_candidate(struct tm_observed_input_manifest *manifest,
                             int root_fd, const char *root_path,
                             const struct tm_observer_candidate *candidate,
                             enum tm_input_kind kind, const char *source_path)
{
    char pending[4096], resolved[4096] = ".", logical_path[4096];
    unsigned int followed = 0;
    if (source_path == NULL ||
        (strcmp(source_path, ".") != 0 &&
         !path_is_canonical(source_path)) ||
        snprintf(pending, sizeof(pending), "%s", source_path) >=
            (int)sizeof(pending)) {
        errno = EINVAL;
        return -1;
    }
    for (;;) {
        char component[4096], rest[4096], full_path[4096];
        char *separator;
        struct stat status;
        size_t component_length;
        if (pending[0] == '\0' || strcmp(pending, ".") == 0) break;
        separator = strchr(pending, '/');
        component_length = separator == NULL ? strlen(pending) :
            (size_t)(separator - pending);
        if (component_length == 0 || component_length >= sizeof(component)) {
            errno = EINVAL;
            return -1;
        }
        memcpy(component, pending, component_length);
        component[component_length] = '\0';
        if (separator == NULL) rest[0] = '\0';
        else snprintf(rest, sizeof(rest), "%s", separator + 1);
        if (strcmp(component, ".") == 0 || component[0] == '\0') {
            snprintf(pending, sizeof(pending), "%s", rest);
            continue;
        }
        if (strcmp(component, "..") == 0 ||
            join_relative(resolved, component, full_path,
                          sizeof(full_path)) < 0) {
            errno = EOPNOTSUPP;
            return -1;
        }
        if (fstatat(root_fd, full_path, &status,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            if ((errno == ENOENT || errno == ENOTDIR) &&
                kind == TM_INPUT_EXISTS) {
                char absent_path[4096];
                if (join_relative(full_path, rest, absent_path,
                                  sizeof(absent_path)) < 0) return -1;
                if (make_logical_path(root_path, absent_path,
                                      logical_path) < 0) return -1;
                return append_observation(manifest, root_fd, kind,
                                          logical_path, absent_path, NULL);
            }
            return -1;
        }
        if (S_ISLNK(status.st_mode) &&
            (rest[0] != '\0' || kind != TM_INPUT_SYMLINK)) {
            char target[4096], replacement[4096];
            char *captured_target = NULL;
            size_t target_length;
            if (++followed > TM_OBSERVED_INPUT_MAX_SYMLINKS) {
                errno = ELOOP;
                return -1;
            }
            if (tm_input_capture_symlink(root_fd, full_path,
                                         &captured_target) < 0) return -1;
            if (make_logical_path(root_path, full_path, logical_path) < 0 ||
                append_observation(manifest, root_fd, TM_INPUT_SYMLINK,
                    logical_path, full_path, captured_target) < 0) {
                free(captured_target);
                return -1;
            }
            target_length = strlen(captured_target);
            if (target_length + strlen(rest) + 2 > sizeof(replacement)) {
                free(captured_target);
                errno = ENAMETOOLONG;
                return -1;
            }
            memcpy(target, captured_target, target_length + 1);
            free(captured_target);
            if (rest[0] == '\0') {
                memcpy(replacement, target, target_length + 1);
            } else {
                size_t rest_length = strlen(rest);
                memcpy(replacement, target, target_length);
                replacement[target_length] = '/';
                memcpy(replacement + target_length + 1, rest,
                       rest_length + 1);
            }
            memcpy(pending, replacement,
                   strlen(replacement) + 1);
            continue;
        }
        snprintf(resolved, sizeof(resolved), "%s", full_path);
        if (rest[0] != '\0' && !S_ISDIR(status.st_mode)) {
            if (kind == TM_INPUT_EXISTS) {
                char absent_path[4096];
                if (join_relative(full_path, rest, absent_path,
                                  sizeof(absent_path)) < 0 ||
                    make_logical_path(root_path, absent_path,
                                      logical_path) < 0) return -1;
                return append_observation(manifest, root_fd, kind,
                                          logical_path, absent_path, NULL);
            }
            errno = ENOTDIR;
            return -1;
        }
        snprintf(pending, sizeof(pending), "%s", rest);
    }
    if (resolved[0] == '\0') snprintf(resolved, sizeof(resolved), ".");
    if (make_logical_path(root_path, resolved, logical_path) < 0) return -1;
    if (strcmp(candidate->kind, "symlink") == 0 &&
        strcmp(resolved, ".") == 0) {
        errno = EINVAL;
        return -1;
    }
    return append_observation(manifest, root_fd, kind, logical_path, resolved,
                              NULL);
}

static int initialize_manifest(struct tm_observed_input_manifest *manifest,
                               size_t capacity)
{
    if (capacity == 0) return 0;
    if (capacity > SIZE_MAX / sizeof(*manifest->items) ||
        capacity > SIZE_MAX / (2 * sizeof(*manifest->owned_fields))) {
        errno = EOVERFLOW;
        return -1;
    }
    manifest->items = calloc(capacity, sizeof(*manifest->items));
    manifest->owned_field_capacity = capacity * 2;
    manifest->owned_fields = calloc(manifest->owned_field_capacity,
                                    sizeof(*manifest->owned_fields));
    if (manifest->items == NULL || manifest->owned_fields == NULL) {
        free_fields(manifest);
        return -1;
    }
    manifest->capacity = capacity;
    return 0;
}

static int capture_one(struct tm_observed_input_manifest *manifest,
                       int root_fd, const char *root_path,
                       const struct tm_observer_candidate *candidate,
                       const char *source_path)
{
    enum tm_input_kind kind;
    if (candidate->external || candidate->path[0] == '\0' ||
        classify_candidate(candidate, &kind) < 0) {
        if (candidate->external || candidate->path[0] == '\0') errno = EXDEV;
        return -1;
    }
    return resolve_candidate(manifest, root_fd, root_path, candidate, kind,
                             source_path);
}

int tm_observer_capture_inputs(const struct tm_observer_report *report,
                               int repository_root_fd,
                               struct tm_observed_input_manifest *manifest)
{
    size_t index, capacity;
    if (report == NULL || repository_root_fd < 0 || manifest == NULL ||
        report->candidate_count > TM_OBSERVER_MAX_CANDIDATES ||
        !tm_observer_report_allows_reuse(report)) {
        errno = EINVAL;
        return -1;
    }
    memset(manifest, 0, sizeof(*manifest));
    if (report->candidate_count >
        SIZE_MAX / (TM_OBSERVED_INPUT_MAX_SYMLINKS + 1)) {
        errno = EOVERFLOW;
        return -1;
    }
    capacity = report->candidate_count *
        (TM_OBSERVED_INPUT_MAX_SYMLINKS + 1);
    if (capacity == 0) return 0;
    if (initialize_manifest(manifest, capacity) < 0) return -1;
    for (index = 0; index < report->candidate_count; index++) {
        if (capture_one(manifest, repository_root_fd, "",
                        &report->candidates[index],
                        report->candidates[index].path) < 0) {
            free_fields(manifest);
            return -1;
        }
    }
    qsort(manifest->items, manifest->count, sizeof(*manifest->items),
          compare_inputs);
    return 0;
}

static int path_is_canonical(const char *path)
{
    const char *part, *cursor;
    if (path == NULL || path[0] == '\0' || path[0] == '/') return 0;
    part = path;
    for (cursor = path;; cursor++) {
        if (*cursor == '/' || *cursor == '\0') {
            size_t length = (size_t)(cursor - part);
            if (length == 0 || (length == 1 && part[0] == '.') ||
                (length == 2 && part[0] == '.' && part[1] == '.')) return 0;
            if (*cursor == '\0') return 1;
            part = cursor + 1;
        }
    }
}

static int root_relative_path(const char *path, const char *root,
                              const char **relative)
{
    size_t length, path_length;
    if (strcmp(path, root) == 0) {
        *relative = ".";
        return 1;
    }
    length = strlen(root);
    path_length = strlen(path);
    if (path_length <= length || strncmp(path, root, length) != 0 ||
        path[length] != '/') return 0;
    *relative = path + length + 1;
    return 1;
}

int tm_observer_capture_snapshot_inputs(
    const struct tm_observer_report *report,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count, struct tm_observed_input_manifest *manifest)
{
    size_t index, root_index, capacity, longest, selected;
    if (report == NULL || root_paths == NULL || root_descriptors == NULL ||
        root_count == 0 || root_count > 10000 || manifest == NULL ||
        report->candidate_count > TM_OBSERVER_MAX_CANDIDATES ||
        !tm_observer_report_allows_reuse(report)) {
        errno = EINVAL;
        return -1;
    }
    memset(manifest, 0, sizeof(*manifest));
    if (report->candidate_count >
        SIZE_MAX / (TM_OBSERVED_INPUT_MAX_SYMLINKS + 1)) {
        errno = EOVERFLOW;
        return -1;
    }
    capacity = report->candidate_count *
        (TM_OBSERVED_INPUT_MAX_SYMLINKS + 1);
    if (capacity == 0) return 0;
    if (initialize_manifest(manifest, capacity) < 0) return -1;
    for (index = 0; index < report->candidate_count; index++) {
        const struct tm_observer_candidate *candidate =
            &report->candidates[index];
        const char *relative = NULL;
        selected = SIZE_MAX;
        longest = 0;
        if (candidate->external || !path_is_canonical(candidate->path)) {
            errno = EXDEV;
            free_fields(manifest);
            return -1;
        }
        for (root_index = 0; root_index < root_count; root_index++) {
            const char *root = root_paths[root_index];
            size_t length;
            const char *candidate_relative;
            if (root_descriptors[root_index] < 0 ||
                !path_is_canonical(root)) continue;
            if (!root_relative_path(candidate->path, root,
                                    &candidate_relative)) continue;
            length = strlen(root);
            if (length > longest) {
                longest = length;
                relative = candidate_relative;
                selected = root_index;
            }
        }
        if (selected == SIZE_MAX || capture_one(manifest,
                root_descriptors[selected], root_paths[selected], candidate,
                relative) < 0) {
            if (selected == SIZE_MAX) errno = EXDEV;
            free_fields(manifest);
            return -1;
        }
    }
    qsort(manifest->items, manifest->count, sizeof(*manifest->items),
          compare_inputs);
    return 0;
}

static const char *candidate_kind(enum tm_input_kind kind)
{
    switch (kind) {
    case TM_INPUT_DIRECTORY: return "directory listing";
    case TM_INPUT_EXISTS: return "absent path";
    case TM_INPUT_FILE: return "opened file";
    case TM_INPUT_SYMLINK: return "symlink";
    }
    return NULL;
}

int tm_observed_inputs_match_snapshots(
    const struct tm_input_observation *inputs, size_t input_count,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count)
{
    struct tm_observed_input_manifest current = {0};
    size_t index, root_index;
    int result = -1;
    if ((input_count > 0 && inputs == NULL) ||
        (root_count > 0 && (root_paths == NULL || root_descriptors == NULL)) ||
        root_count > 10000 || input_count > TM_OBSERVED_INPUT_MAX_ITEMS ||
        (input_count > 0 && root_count == 0)) {
        errno = EINVAL;
        return -1;
    }
    if (input_count == 0) return 0;
    if (initialize_manifest(&current, input_count) < 0) goto done;
    for (index = 0; index < input_count; index++) {
        struct tm_observer_candidate candidate = {0};
        const char *kind = candidate_kind(inputs[index].kind);
        const char *relative = NULL;
        size_t longest = 0, selected = SIZE_MAX;
        if (kind == NULL || inputs[index].path == NULL ||
            strlen(inputs[index].path) >= sizeof(candidate.path)) {
            errno = EINVAL;
            goto done;
        }
        strcpy(candidate.kind, kind);
        strcpy(candidate.path, inputs[index].path);
        for (root_index = 0; root_index < root_count; root_index++) {
            const char *candidate_relative;
            size_t length;
            if (root_descriptors[root_index] < 0 ||
                !path_is_canonical(root_paths[root_index]) ||
                !root_relative_path(candidate.path, root_paths[root_index],
                                    &candidate_relative)) continue;
            length = strlen(root_paths[root_index]);
            if (length > longest) {
                longest = length;
                relative = candidate_relative;
                selected = root_index;
            }
        }
        if (selected == SIZE_MAX) {
            result = 1;
            goto done;
        }
        if (capture_one(&current, root_descriptors[selected],
                        root_paths[selected], &candidate, relative) < 0) {
            result = errno == ENOMEM || errno == EOVERFLOW ? -1 : 1;
            goto done;
        }
    }
    qsort(current.items, current.count, sizeof(*current.items), compare_inputs);
    if (current.count != input_count) {
        result = 1;
        goto done;
    }
    for (index = 0; index < input_count; index++) {
        if (strcmp(current.items[index].path, inputs[index].path) != 0 ||
            !input_equal(&current.items[index], &inputs[index])) {
            result = 1;
            goto done;
        }
    }
    result = 0;
done:
    tm_observed_input_manifest_clear(&current);
    return result;
}
