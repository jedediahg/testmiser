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
                       const struct tm_observer_candidate *candidate)
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
        if (tm_input_capture_file(root_fd, candidate->path, digest) < 0)
            return -1;
    } else if (kind == TM_INPUT_EXISTS) {
        if (tm_input_capture_exists(root_fd, candidate->path, &exists) < 0 ||
            exists) {
            if (exists) errno = ESTALE;
            return -1;
        }
    } else if (tm_input_capture_symlink(root_fd, candidate->path,
                                        &target) < 0) {
        return -1;
    }

    for (index = 0; index < manifest->count; index++) {
        observation = &manifest->items[index];
        if (strcmp(observation->path, candidate->path) != 0) continue;
        free(target);
        if (observation->kind == kind) return 0;
        errno = EINVAL;
        return -1;
    }

    observation = &manifest->items[manifest->count];
    memset(observation, 0, sizeof(*observation));
    if (own_field(manifest, candidate->path, &observation->path) < 0) {
        free(target);
        return -1;
    }
    observation->kind = kind;
    observation->exists = 0;
    if (kind == TM_INPUT_FILE) {
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
                        &report->candidates[index]) < 0) {
            free_fields(manifest);
            return -1;
        }
    }
    qsort(manifest->items, manifest->count, sizeof(*manifest->items),
          compare_inputs);
    return 0;
}
