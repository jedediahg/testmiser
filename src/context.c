#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tm/context.h"
#include "tm/digest.h"

static int valid_environment(const struct tm_json_value *environment)
{
    size_t i;
    if (tm_json_typeof(environment) != TM_JSON_OBJECT) return 0;
    for (i = 0; i < tm_json_size(environment); i++) {
        const char *name = tm_json_object_key_at(environment, i);
        size_t j;
        if (name == NULL || tm_json_typeof(
                tm_json_object_value_at(environment, i)) != TM_JSON_STRING ||
            !((name[0] >= 'A' && name[0] <= 'Z') ||
              (name[0] >= 'a' && name[0] <= 'z') || name[0] == '_'))
            return 0;
        for (j = 1; name[j] != '\0'; j++)
            if (!((name[j] >= 'A' && name[j] <= 'Z') ||
                  (name[j] >= 'a' && name[j] <= 'z') ||
                  (name[j] >= '0' && name[j] <= '9') || name[j] == '_'))
                return 0;
    }
    return 1;
}

int tm_context_fingerprint(const struct tm_json_value *environment,
                           const struct tm_json_value *execution_context,
                           char output[72])
{
    static const unsigned char prefix[] = "tm-context-v2\0";
    static const unsigned char object_prefix[] = "{\"environment\":";
    static const unsigned char separator[] = ",\"execution_context\":";
    unsigned char *environment_json = NULL;
    unsigned char *context_json = NULL;
    unsigned char *identity = NULL;
    size_t environment_length = 0, context_length = 0;
    size_t prefix_length = sizeof(prefix) - 1;
    size_t object_prefix_length = sizeof(object_prefix) - 1;
    size_t separator_length = sizeof(separator) - 1;
    size_t identity_length;
    char hex[65];
    int result = -1;

    if (!valid_environment(environment) ||
        tm_json_typeof(execution_context) != TM_JSON_OBJECT || output == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (tm_json_canonicalize(environment, &environment_json,
                             &environment_length) < 0 ||
        tm_json_canonicalize(execution_context, &context_json,
                             &context_length) < 0) goto done;
    if (environment_length > SIZE_MAX - context_length - prefix_length -
                              object_prefix_length - separator_length - 1) {
        errno = EOVERFLOW;
        goto done;
    }
    identity_length = prefix_length + object_prefix_length + environment_length +
                      separator_length + context_length + 1;
    identity = malloc(identity_length);
    if (identity == NULL) goto done;
    memcpy(identity, prefix, prefix_length);
    memcpy(identity + prefix_length, object_prefix, object_prefix_length);
    memcpy(identity + prefix_length + object_prefix_length, environment_json,
           environment_length);
    memcpy(identity + prefix_length + object_prefix_length + environment_length,
           separator, separator_length);
    memcpy(identity + prefix_length + object_prefix_length + environment_length +
           separator_length, context_json,
           context_length);
    identity[identity_length - 1] = '}';
    if (tm_sha256_bytes(identity, identity_length, hex) < 0) goto done;
    memcpy(output, "sha256:", 7);
    memcpy(output + 7, hex, sizeof(hex));
    result = 0;
done:
    free(environment_json);
    free(context_json);
    free(identity);
    return result;
}
