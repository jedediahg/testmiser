#ifndef TM_OBSERVED_INPUTS_H
#define TM_OBSERVED_INPUTS_H

#include "tm/observer.h"
#include "tm/verification.h"

struct tm_observed_input_manifest {
    struct tm_input_observation *items;
    size_t count;
    char **owned_fields;
    size_t owned_field_count;
};

/* Capture the complete, stable observer report as a deduplicated manifest.
 * Unsupported, external, conflicting, or unsafe candidates fail closed. */
int tm_observer_capture_inputs(const struct tm_observer_report *report,
                               int repository_root_fd,
                               struct tm_observed_input_manifest *manifest);
void tm_observed_input_manifest_clear(
    struct tm_observed_input_manifest *manifest);

#endif
