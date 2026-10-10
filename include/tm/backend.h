#ifndef TM_BACKEND_H
#define TM_BACKEND_H

#include "tm/observer.h"
#include "tm/observed_inputs.h"

struct tm_profile;

/* Try the approved Bubblewrap view. Return 1 if the command ran, 0 when the
 * host cannot enforce the view (caller may run once, uncached), or -1 when
 * local backend setup failed before launch. */
int tm_backend_run(const struct tm_profile *profile,
                   const char *runtime_root, const char *repository_root,
                   const char *const *output_roots, size_t output_root_count,
                   char **command, int explain,
                   struct tm_observer_report *report,
                   struct tm_observed_input_manifest *inputs,
                   int *command_result);

#endif
