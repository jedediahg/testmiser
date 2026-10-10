#ifndef TM_ATTEMPT_H
#define TM_ATTEMPT_H

#include <stddef.h>

struct tm_attempt_state {
    int directory_fd;
    int blocked_all;
    int stale_running;
    char **blocked_fingerprints;
    size_t blocked_count;
};

enum tm_attempt_outcome {
    TM_ATTEMPT_RUN_ONLY,
    TM_ATTEMPT_FAILED,
    TM_ATTEMPT_QUARANTINED,
    TM_ATTEMPT_ELIGIBLE_SUCCESS
};

int tm_attempt_state_open_default(const char *repository_id,
                                  const char *command_fingerprint,
                                  const char *profile_digest,
                                  const char *context_digest,
                                  struct tm_attempt_state *state);
int tm_attempt_state_begin(struct tm_attempt_state *state);
int tm_attempt_state_finish(struct tm_attempt_state *state,
                            enum tm_attempt_outcome outcome,
                            const char *verification_fingerprint);
int tm_attempt_state_blocks(const struct tm_attempt_state *state,
                            const char *verification_fingerprint);
void tm_attempt_state_clear(struct tm_attempt_state *state);

#endif
