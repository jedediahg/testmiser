#ifndef TM_IDENTITY_H
#define TM_IDENTITY_H

#include <stddef.h>

struct tm_command_identity {
    const char *repository_id;
    const char *const *argv;
    size_t argc;
    const char *working_directory;
    const char *const *inputs;
    size_t input_count;
    const char *const *outputs;
    size_t output_count;
};

/* Return a sha256: prefixed portable command identity. */
int tm_command_fingerprint(const struct tm_command_identity *identity,
                           char output[72]);

#endif
