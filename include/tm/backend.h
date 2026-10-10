#ifndef TM_BACKEND_H
#define TM_BACKEND_H

#include "tm/observer.h"
#include "tm/observed_inputs.h"
#include "tm/outputs.h"

struct tm_profile;
struct tm_snapshot;

/* Resolve the Bubblewrap executable and identify its stable contents. */
int tm_backend_executable_identity(char **resolved_path, char digest[72]);

/* Check whether the approved view can be enforced without running the test. */
int tm_backend_preflight(const struct tm_profile *profile,
                        const char *runtime_root,
                        const char *repository_root,
                        const struct tm_snapshot *snapshot);

/* Try the approved Bubblewrap view. Return 1 if the command ran, 0 when the
 * host cannot enforce the view (caller may run once, uncached), or -1 when
 * local backend setup failed before launch. */
int tm_backend_run(const struct tm_profile *profile,
                   const char *runtime_root, const char *repository_root,
                   const char *const *output_roots, size_t output_root_count,
                   char **command, int explain,
                   struct tm_observer_report *report,
                   struct tm_observed_input_manifest *inputs,
                   struct tm_output_manifest *outputs,
                   int *command_result);

#endif
