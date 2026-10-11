#ifndef TM_OBSERVED_INPUTS_H
#define TM_OBSERVED_INPUTS_H

#include "tm/observer.h"
#include "tm/verification.h"

#define TM_OBSERVED_INPUT_MAX_SYMLINKS 40
#define TM_OBSERVED_INPUT_MAX_ITEMS \
    (TM_OBSERVER_MAX_CANDIDATES * (TM_OBSERVED_INPUT_MAX_SYMLINKS + 1))

struct tm_observed_input_manifest {
    struct tm_input_observation *items;
    size_t count;
    size_t capacity;
    char **owned_fields;
    size_t owned_field_count;
    size_t owned_field_capacity;
};

/* Capture the complete, stable observer report as a deduplicated manifest.
 * Unsupported, external, conflicting, or unsafe candidates fail closed. */
int tm_observer_capture_inputs(const struct tm_observer_report *report,
                               int repository_root_fd,
                               struct tm_observed_input_manifest *manifest);
/* As above, but resolve each repository-relative candidate through the
 * approved-root snapshots used by the controlled workspace. */
int tm_observer_capture_snapshot_inputs(
    const struct tm_observer_report *report,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count, struct tm_observed_input_manifest *manifest);
/* Compare an existing result manifest to approved-root snapshot contents.
 * Return 0 for a match, 1 for changed/unsafe input, and -1 for bad arguments
 * or resource failures. */
int tm_observed_inputs_match_snapshots(
    const struct tm_input_observation *inputs, size_t input_count,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count);
void tm_observed_input_manifest_clear(
    struct tm_observed_input_manifest *manifest);

#endif
