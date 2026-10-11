#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tm/attempt.h"

int main(void)
{
    char cache[] = "/tmp/tm-attempt-XXXXXX";
    const char *a = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *b = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const char *cmd = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const char *profile = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const char *context = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    struct tm_attempt_state state = {.directory_fd = -1};
    int status = 1;
    if (mkdtemp(cache) == NULL || setenv("XDG_CACHE_HOME", cache, 1) < 0 ||
        tm_attempt_state_open_default("attempt-test", cmd, profile, context,
                                      &state) < 0) { perror("attempt open 1"); goto done; }
    if (tm_attempt_state_begin(&state) < 0) { perror("attempt begin 1"); goto done; }
    if (tm_attempt_state_finish(&state, TM_ATTEMPT_FAILED, a) < 0) { perror("attempt fail finish"); goto done; }
    tm_attempt_state_clear(&state);
    if (tm_attempt_state_open_default("attempt-test", cmd, profile, context,
                                      &state) < 0) { perror("attempt open 2"); goto done; }
    if (
        !tm_attempt_state_blocks(&state, a) ||
        tm_attempt_state_blocks(&state, b)) { fprintf(stderr, "attempt exact block failed\n"); goto done; }
    if (tm_attempt_state_begin(&state) < 0 ||
        tm_attempt_state_finish(&state, TM_ATTEMPT_ELIGIBLE_SUCCESS, a) < 0 ||
        tm_attempt_state_blocks(&state, a)) { perror("attempt success clear"); goto done; }
    if (tm_attempt_state_begin(&state) < 0 ||
        tm_attempt_state_finish(&state, TM_ATTEMPT_QUARANTINED, a) < 0 ||
        !tm_attempt_state_blocks(&state, a)) { perror("attempt quarantine"); goto done; }
    tm_attempt_state_clear(&state);
    if (tm_attempt_state_open_default("attempt-test", cmd, profile, context,
                                      &state) < 0 ||
        !tm_attempt_state_blocks(&state, a)) {
        fprintf(stderr, "quarantine was not retained across reopen\n");
        goto done;
    }
    if (tm_attempt_state_begin(&state) < 0 ||
        tm_attempt_state_finish(&state, TM_ATTEMPT_ELIGIBLE_SUCCESS, a) < 0 ||
        tm_attempt_state_blocks(&state, a)) {
        fprintf(stderr, "eligible success did not clear quarantine\n");
        goto done;
    }
    tm_attempt_state_clear(&state);
    if (tm_attempt_state_open_default("attempt-test", cmd, profile, context,
                                      &state) < 0 ||
        tm_attempt_state_blocks(&state, a) ||
        tm_attempt_state_begin(&state) < 0 ||
        tm_attempt_state_finish(&state, TM_ATTEMPT_QUARANTINED, a) < 0) {
        fprintf(stderr, "quarantine could not be recreated after recovery\n");
        goto done;
    }
    tm_attempt_state_clear(&state);
    if (tm_attempt_state_open_default("attempt-test", cmd, profile, context,
                                      &state) < 0 ||
        !tm_attempt_state_blocks(&state, a)) {
        fprintf(stderr, "recreated quarantine did not persist\n");
        goto done;
    }
    if (tm_attempt_state_resolve(&state, a) < 0 ||
        tm_attempt_state_blocks(&state, a)) {
        fprintf(stderr, "explicit fingerprint resolution failed\n");
        goto done;
    }
    tm_attempt_state_clear(&state);
    {
        const char *other_command =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if (tm_attempt_state_open_default("attempt-test", other_command,
                profile, context, &state) < 0 ||
            tm_attempt_state_begin(&state) < 0) goto done;
        errno = 0;
        if (tm_attempt_state_finish(&state,
                (enum tm_attempt_outcome)99, a) == 0 || errno != EINVAL) {
            fprintf(stderr, "invalid attempt outcome was accepted\n");
            goto done;
        }
        tm_attempt_state_clear(&state);
        if (tm_attempt_state_open_default("attempt-test", other_command,
                profile, context, &state) < 0 || !state.stale_running ||
            !state.blocked_all || !tm_attempt_state_blocks(&state, a)) {
            fprintf(stderr, "invalid outcome cleared the durable running marker\n");
            goto done;
        }
        if (tm_attempt_state_resolve(&state, NULL) < 0) goto done;
        tm_attempt_state_clear(&state);

        if (tm_attempt_state_open_default("attempt-test", other_command,
                profile, context, &state) < 0 ||
            tm_attempt_state_begin(&state) < 0) goto done;
        tm_attempt_state_clear(&state);
        if (tm_attempt_state_open_default("attempt-test", other_command,
                profile, context, &state) < 0 ||
            !state.stale_running || !state.blocked_all ||
            !tm_attempt_state_blocks(&state, a)) {
            fprintf(stderr, "interrupted attempt did not block all fingerprints\n");
            goto done;
        }
        if (tm_attempt_state_resolve(&state, NULL) < 0 ||
            state.blocked_all || tm_attempt_state_blocks(&state, a)) {
            fprintf(stderr, "explicit scope resolution failed\n");
            goto done;
        }
        tm_attempt_state_clear(&state);
        if (tm_attempt_state_open_default("attempt-test", other_command,
                profile, context, &state) < 0 || state.blocked_all ||
            state.stale_running || tm_attempt_state_blocks(&state, a)) {
            fprintf(stderr, "scope resolution did not persist: all=%d stale=%d blocks=%d count=%zu\n",
                    state.blocked_all, state.stale_running,
                    tm_attempt_state_blocks(&state, a), state.blocked_count);
            goto done;
        }
    }
    status = 0;
done:
    tm_attempt_state_clear(&state);
    if (status != 0) fprintf(stderr, "attempt state test failed\n");
    return status;
}
