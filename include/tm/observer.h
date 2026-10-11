#ifndef TM_OBSERVER_H
#define TM_OBSERVER_H

#include <stddef.h>

/* Repository-relative paths discovered through traced filesystem access.
 * External observations are marked but their host paths are never returned. */
#define TM_OBSERVER_MAX_CANDIDATES 512
#define TM_OBSERVER_PATH_SIZE 1024

enum tm_observer_ineligibility {
    TM_OBSERVER_INELIGIBLE_NETWORK = 1U << 0,
    TM_OBSERVER_INELIGIBLE_MUTATION = 1U << 1,
    TM_OBSERVER_INELIGIBLE_METADATA = 1U << 2,
    TM_OBSERVER_INELIGIBLE_DIRECTORY = 1U << 3,
    TM_OBSERVER_INELIGIBLE_DESCRIPTOR = 1U << 4,
    TM_OBSERVER_INELIGIBLE_UNSUPPORTED = 1U << 5,
    TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE = 1U << 6,
    TM_OBSERVER_INELIGIBLE_DESCENDANT = 1U << 7,
    TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT = 1U << 8,
    TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW = 1U << 9,
    TM_OBSERVER_INELIGIBLE_UNMODELED_ERROR = 1U << 10,
    TM_OBSERVER_INELIGIBLE_CONTEXT = 1U << 11
};

struct tm_observer_candidate {
    char kind[32];
    char path[TM_OBSERVER_PATH_SIZE];
    int external;
};

struct tm_observer_report {
    size_t candidate_count;
    struct tm_observer_candidate candidates[TM_OBSERVER_MAX_CANDIDATES];
    unsigned int ineligibility_reasons;
    int observation_complete;
    int stable_input_view;
};

/* True only when syscall observation completed and found no unsupported or
 * nondeterministic effects. This is necessary, but not sufficient, for reuse. */
int tm_observer_report_allows_reuse(const struct tm_observer_report *report);
/* Return a stable user-facing description for one ineligibility bit. */
const char *tm_observer_ineligibility_description(unsigned int reason);

int tm_observe_and_run(char **command, int explain, char *const environment[],
                       const char *repository_root,
                       struct tm_observer_report *report);
/* Run a launcher under observation while allowing it to inherit only the
 * listed descriptors (for example, pinned Bubblewrap bind sources). */
int tm_observe_and_run_with_fds(char **command, int explain,
                                char *const environment[],
                                const char *repository_root,
                                const int *preserved_fds,
                                size_t preserved_fd_count,
                                int null_stdin, int set_umask_022,
                                const char *start_after_exec,
                                /* Set only after enforcing the runtime-root
                                 * and scratch mount contract. */
                                int controlled_runtime,
                                const char *const *output_roots,
                                size_t output_root_count,
                                struct tm_observer_report *report);
/* Extended form for backends that enforce namespace UID/GID zero. */
int tm_observe_and_run_with_fds_identity(char **command, int explain,
                                char *const environment[],
                                const char *repository_root,
                                const int *preserved_fds,
                                size_t preserved_fd_count,
                                int null_stdin, int set_umask_022,
                                const char *start_after_exec,
                                int controlled_runtime,
                                int normalized_identity,
                                const char *const *output_roots,
                                size_t output_root_count,
                                struct tm_observer_report *report);

#endif
