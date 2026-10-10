#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tm/digest.h"
#include "tm/verification.h"

struct buffer {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
};

static const char *kind_name(enum tm_input_kind kind)
{
    switch (kind) {
    case TM_INPUT_DIRECTORY:
        return "directory";
    case TM_INPUT_EXISTS:
        return "exists";
    case TM_INPUT_FILE:
        return "file";
    case TM_INPUT_SYMLINK:
        return "symlink";
    }
    return NULL;
}

static int valid_utf8(const unsigned char *text)
{
    while (*text != 0) {
        unsigned int first = *text++;
        unsigned int count;
        unsigned int minimum;
        unsigned int codepoint;
        unsigned int index;

        if (first < 0x80) {
            continue;
        }
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1;
            minimum = 0x80;
            codepoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2;
            minimum = 0x800;
            codepoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3;
            minimum = 0x10000;
            codepoint = first & 0x07;
        } else {
            return 0;
        }
        for (index = 0; index < count; index++) {
            unsigned int next = *text++;
            if (next == 0 || (next & 0xc0) != 0x80) {
                return 0;
            }
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
            return 0;
        }
    }
    return 1;
}

static int valid_path(const char *path)
{
    const char *component;
    const char *cursor;

    if (path == NULL || path[0] == '\0' || path[0] == '/' ||
        !valid_utf8((const unsigned char *)path)) {
        return 0;
    }
    component = path;
    for (cursor = path;; cursor++) {
        if (*cursor == '/' || *cursor == '\0') {
            size_t length = (size_t)(cursor - component);
            if (length == 0 || (length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' && component[1] == '.')) {
                return 0;
            }
            if (*cursor == '\0') {
                return 1;
            }
            component = cursor + 1;
        }
    }
}

static int valid_working_directory(const char *path)
{
    return (path != NULL && strcmp(path, ".") == 0) || valid_path(path);
}

static int valid_digest(const char *digest)
{
    size_t index;

    if (digest == NULL || strlen(digest) != 71 ||
        memcmp(digest, "sha256:", 7) != 0) {
        return 0;
    }
    for (index = 7; index < 71; index++) {
        if (!((digest[index] >= '0' && digest[index] <= '9') ||
              (digest[index] >= 'a' && digest[index] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int reserve(struct buffer *buffer, size_t additional)
{
    size_t required;
    size_t capacity;
    unsigned char *bytes;

    if (additional > SIZE_MAX - buffer->length) {
        errno = EOVERFLOW;
        return -1;
    }
    required = buffer->length + additional;
    if (required <= buffer->capacity) {
        return 0;
    }
    capacity = buffer->capacity == 0 ? 256 : buffer->capacity;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2) {
            capacity = required;
            break;
        }
        capacity *= 2;
    }
    bytes = realloc(buffer->bytes, capacity);
    if (bytes == NULL) {
        errno = ENOMEM;
        return -1;
    }
    buffer->bytes = bytes;
    buffer->capacity = capacity;
    return 0;
}

static int append_bytes(struct buffer *buffer, const void *data, size_t length)
{
    if (reserve(buffer, length) < 0) {
        return -1;
    }
    memcpy(buffer->bytes + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

static int append_literal(struct buffer *buffer, const char *text)
{
    return append_bytes(buffer, text, strlen(text));
}

static int append_string(struct buffer *buffer, const char *value)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *cursor = (const unsigned char *)value;

    if (value == NULL || !valid_utf8(cursor)) {
        errno = EILSEQ;
        return -1;
    }
    if (append_literal(buffer, "\"") < 0) {
        return -1;
    }
    while (*cursor != 0) {
        unsigned char character = *cursor++;
        char escaped[6];

        if (character == '"' || character == '\\') {
            escaped[0] = '\\';
            escaped[1] = (char)character;
            if (append_bytes(buffer, escaped, 2) < 0) {
                return -1;
            }
        } else if (character == '\b' || character == '\t' ||
                   character == '\n' || character == '\f' ||
                   character == '\r') {
            escaped[0] = '\\';
            escaped[1] = character == '\b' ? 'b' :
                         character == '\t' ? 't' :
                         character == '\n' ? 'n' :
                         character == '\f' ? 'f' : 'r';
            if (append_bytes(buffer, escaped, 2) < 0) {
                return -1;
            }
        } else if (character < 0x20) {
            escaped[0] = '\\';
            escaped[1] = 'u';
            escaped[2] = '0';
            escaped[3] = '0';
            escaped[4] = hex[character >> 4];
            escaped[5] = hex[character & 0x0f];
            if (append_bytes(buffer, escaped, sizeof(escaped)) < 0) {
                return -1;
            }
        } else if (append_bytes(buffer, &character, 1) < 0) {
            return -1;
        }
    }
    return append_literal(buffer, "\"");
}

static int compare_input(const void *left, const void *right)
{
    const struct tm_input_observation *const *a = left;
    const struct tm_input_observation *const *b = right;
    int path_order = strcmp((*a)->path, (*b)->path);

    if (path_order != 0) {
        return path_order;
    }
    return strcmp(kind_name((*a)->kind), kind_name((*b)->kind));
}

static int same_input(const struct tm_input_observation *a,
                      const struct tm_input_observation *b)
{
    return a->kind == b->kind && strcmp(a->path, b->path) == 0 &&
           a->exists == b->exists &&
           ((a->digest == NULL && b->digest == NULL) ||
            (a->digest != NULL && b->digest != NULL &&
             strcmp(a->digest, b->digest) == 0)) &&
           ((a->target == NULL && b->target == NULL) ||
            (a->target != NULL && b->target != NULL &&
             strcmp(a->target, b->target) == 0));
}

static int append_input(struct buffer *buffer,
                        const struct tm_input_observation *input)
{
    const char *kind = kind_name(input->kind);

    if (kind == NULL || !valid_path(input->path)) {
        errno = EINVAL;
        return -1;
    }
    if (append_literal(buffer, "{\"kind\":") < 0 ||
        append_string(buffer, kind) < 0 ||
        append_literal(buffer, ",\"path\":") < 0 ||
        append_string(buffer, input->path) < 0) {
        return -1;
    }
    switch (input->kind) {
    case TM_INPUT_FILE:
    case TM_INPUT_DIRECTORY:
        if (!valid_digest(input->digest) || input->target != NULL ||
            input->exists != 0) {
            errno = EINVAL;
            return -1;
        }
        if (append_literal(buffer, ",\"sha256\":") < 0 ||
            append_string(buffer, input->digest) < 0) {
            return -1;
        }
        break;
    case TM_INPUT_EXISTS:
        if ((input->exists != 0 && input->exists != 1) ||
            input->digest != NULL || input->target != NULL) {
            errno = EINVAL;
            return -1;
        }
        if (append_literal(buffer, input->exists ? ",\"state\":true" :
                                                    ",\"state\":false") < 0) {
            return -1;
        }
        break;
    case TM_INPUT_SYMLINK:
        if (!valid_path(input->target) || input->digest != NULL ||
            input->exists != 0) {
            errno = EINVAL;
            return -1;
        }
        if (append_literal(buffer, ",\"target\":") < 0 ||
            append_string(buffer, input->target) < 0) {
            return -1;
        }
        break;
    }
    return append_literal(buffer, "}");
}

static int append_inputs(struct buffer *buffer,
                         const struct tm_verification_identity *identity)
{
    const struct tm_input_observation **sorted;
    size_t index;
    size_t emitted = 0;

    if (identity->input_count > SIZE_MAX / sizeof(*sorted)) {
        errno = EOVERFLOW;
        return -1;
    }
    sorted = identity->input_count == 0 ? NULL :
        malloc(identity->input_count * sizeof(*sorted));
    if (identity->input_count > 0 && sorted == NULL) {
        errno = ENOMEM;
        return -1;
    }
    for (index = 0; index < identity->input_count; index++) {
        sorted[index] = &identity->inputs[index];
        if (kind_name(sorted[index]->kind) == NULL ||
            !valid_path(sorted[index]->path)) {
            free(sorted);
            errno = EINVAL;
            return -1;
        }
    }
    if (identity->input_count > 1) {
        qsort(sorted, identity->input_count, sizeof(*sorted), compare_input);
    }
    if (append_literal(buffer, "[") < 0) {
        free(sorted);
        return -1;
    }
    for (index = 0; index < identity->input_count; index++) {
        if (index > 0 && strcmp(sorted[index]->path,
                                sorted[index - 1]->path) == 0 &&
            sorted[index]->kind == sorted[index - 1]->kind) {
            if (!same_input(sorted[index], sorted[index - 1])) {
                free(sorted);
                errno = EINVAL;
                return -1;
            }
            continue;
        }
        if (emitted++ > 0 && append_literal(buffer, ",") < 0) {
            free(sorted);
            return -1;
        }
        if (append_input(buffer, sorted[index]) < 0) {
            free(sorted);
            return -1;
        }
    }
    free(sorted);
    return append_literal(buffer, "]");
}

static int build_preimage(struct buffer *buffer,
                          const struct tm_verification_identity *identity)
{
    static const unsigned char domain[] = "tm-verification-v2";
    struct buffer json = {0};
    int result = -1;

    if (append_literal(&json, "{\"environment\":{\"context_digest\":") < 0 ||
        append_string(&json, identity->context_digest) < 0 ||
        append_literal(&json, ",\"profile_digest\":") < 0 ||
        append_string(&json, identity->profile_digest) < 0 ||
        append_literal(&json, ",\"runtime_digest\":") < 0 ||
        append_string(&json, identity->runtime_digest) < 0 ||
        append_literal(&json, "},\"identity\":{\"command_fingerprint\":") < 0 ||
        append_string(&json, identity->command_fingerprint) < 0 ||
        append_literal(&json, ",\"working_directory\":") < 0 ||
        append_string(&json, identity->working_directory) < 0 ||
        append_literal(&json, "},\"inputs\":") < 0 ||
        append_inputs(&json, identity) < 0 ||
        append_literal(&json, ",\"repository_id\":") < 0 ||
        append_string(&json, identity->repository_id) < 0 ||
        append_literal(&json, ",\"schema_version\":2,\"tm_semantics_version\":2}") < 0 ||
        json.length > SIZE_MAX - sizeof(domain)) {
        goto done;
    }
    if (reserve(buffer, sizeof(domain) + json.length) < 0) {
        goto done;
    }
    memcpy(buffer->bytes, domain, sizeof(domain));
    memcpy(buffer->bytes + sizeof(domain), json.bytes, json.length);
    buffer->length = sizeof(domain) + json.length;
    result = 0;

done:
    free(json.bytes);
    return result;
}

int tm_verification_fingerprint(const struct tm_verification_identity *identity,
                                char output[72])
{
    struct buffer preimage = {0};
    char digest[65];
    int result = -1;

    if (identity == NULL || output == NULL || identity->repository_id == NULL ||
        identity->command_fingerprint == NULL ||
        identity->working_directory == NULL ||
        identity->profile_digest == NULL || identity->runtime_digest == NULL ||
        identity->context_digest == NULL ||
        (identity->input_count > 0 && identity->inputs == NULL) ||
        !valid_digest(identity->command_fingerprint) ||
        !valid_digest(identity->profile_digest) ||
        !valid_digest(identity->runtime_digest) ||
        !valid_digest(identity->context_digest) ||
        !valid_utf8((const unsigned char *)identity->repository_id) ||
        !valid_working_directory(identity->working_directory)) {
        errno = EINVAL;
        return -1;
    }
    if (build_preimage(&preimage, identity) < 0) {
        goto done;
    }
    if (tm_sha256_bytes(preimage.bytes, preimage.length, digest) == 0) {
        memcpy(output, "sha256:", 7);
        memcpy(output + 7, digest, sizeof(digest));
        result = 0;
    }

done:
    free(preimage.bytes);
    return result;
}
