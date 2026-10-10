#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

static int capture_one(struct tm_observed_input_manifest *manifest,
                       int root_fd,
                       const struct tm_observer_candidate *candidate,
                       const char *source_path)
{
    struct tm_input_observation *observation;
    enum tm_input_kind kind;
    size_t index;
    char digest[72];
    char *target = NULL;
    int exists = 1;

    if (candidate->external || candidate->path[0] == '\0' ||
        classify_candidate(candidate, &kind) < 0) {
        if (candidate->external || candidate->path[0] == '\0') errno = EXDEV;
        return -1;
    }
    if (kind == TM_INPUT_FILE) {
        if (tm_input_capture_file(root_fd, source_path, digest) < 0)
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
    } else if (tm_input_capture_symlink(root_fd, source_path,
                                        &target) < 0) {
        return -1;
    }

    for (index = 0; index < manifest->count; index++) {
        observation = &manifest->items[index];
        if (strcmp(observation->path, candidate->path) != 0) continue;
        {
            struct tm_input_observation current = {candidate->path, kind,
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

    observation = &manifest->items[manifest->count];
    memset(observation, 0, sizeof(*observation));
    if (own_field(manifest, candidate->path, &observation->path) < 0) {
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
    capacity = report->candidate_count;
    if (capacity == 0) return 0;
    if (capacity > SIZE_MAX / sizeof(*manifest->items) ||
        capacity > SIZE_MAX / (2 * sizeof(*manifest->owned_fields))) {
        errno = EOVERFLOW;
        return -1;
    }
    manifest->items = calloc(capacity, sizeof(*manifest->items));
    manifest->owned_fields = calloc(capacity * 2,
                                    sizeof(*manifest->owned_fields));
    if (manifest->items == NULL || manifest->owned_fields == NULL) {
        free_fields(manifest);
        return -1;
    }
    for (index = 0; index < report->candidate_count; index++) {
        if (capture_one(manifest, repository_root_fd,
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
    capacity = report->candidate_count;
    if (capacity == 0) return 0;
    if (capacity > SIZE_MAX / sizeof(*manifest->items) ||
        capacity > SIZE_MAX / (2 * sizeof(*manifest->owned_fields))) {
        errno = EOVERFLOW;
        return -1;
    }
    manifest->items = calloc(capacity, sizeof(*manifest->items));
    manifest->owned_fields = calloc(capacity * 2,
                                    sizeof(*manifest->owned_fields));
    if (manifest->items == NULL || manifest->owned_fields == NULL) {
        free_fields(manifest);
        return -1;
    }
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
                root_descriptors[selected], candidate, relative) < 0) {
            if (selected == SIZE_MAX) errno = EXDEV;
            free_fields(manifest);
            return -1;
        }
    }
    qsort(manifest->items, manifest->count, sizeof(*manifest->items),
          compare_inputs);
    return 0;
}
