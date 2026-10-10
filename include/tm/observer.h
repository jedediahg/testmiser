#ifndef TM_OBSERVER_H
#define TM_OBSERVER_H

#include <stddef.h>

/* Repository-relative paths discovered through traced filesystem access.
 * External observations are marked but their host paths are never returned. */
#define TM_OBSERVER_MAX_CANDIDATES 512
#define TM_OBSERVER_PATH_SIZE 1024

struct tm_observer_candidate {
    char kind[32];
    char path[TM_OBSERVER_PATH_SIZE];
    int external;
};

struct tm_observer_report {
    size_t candidate_count;
    struct tm_observer_candidate candidates[TM_OBSERVER_MAX_CANDIDATES];
};

int tm_observe_and_run(char **command, int explain, char *const environment[],
                       const char *repository_root,
                       struct tm_observer_report *report);

#endif
