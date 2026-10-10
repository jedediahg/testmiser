#ifndef TM_VERIFICATION_H
#define TM_VERIFICATION_H

#include <stddef.h>

enum tm_input_kind {
    TM_INPUT_DIRECTORY,
    TM_INPUT_EXISTS,
    TM_INPUT_FILE,
    TM_INPUT_SYMLINK
};

struct tm_input_observation {
    const char *path;
    enum tm_input_kind kind;
    const char *digest;
    const char *target;
    int exists;
};

struct tm_verification_identity {
    const char *repository_id;
    const char *command_fingerprint;
    const char *working_directory;
    const char *profile_digest;
    const char *runtime_digest;
    const char *context_digest;
    const struct tm_input_observation *inputs;
    size_t input_count;
};

/* Return a sha256: prefixed v2 fingerprint over canonical effective inputs. */
int tm_verification_fingerprint(const struct tm_verification_identity *identity,
                                char output[72]);

#endif
