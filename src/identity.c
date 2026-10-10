#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tm/digest.h"
#include "tm/identity.h"

struct json_buffer {
    unsigned char *bytes;
    size_t length;
    size_t capacity;
};

static int valid_utf8(const unsigned char *text)
{
    while (*text != 0) {
        unsigned int first = *text++;
        unsigned int continuation_count;
        unsigned int minimum;
        unsigned int codepoint;
        unsigned int index;

        if (first < 0x80) {
            continue;
        }
        if (first >= 0xc2 && first <= 0xdf) {
            continuation_count = 1;
            minimum = 0x80;
            codepoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            continuation_count = 2;
            minimum = 0x800;
            codepoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            continuation_count = 3;
            minimum = 0x10000;
            codepoint = first & 0x07;
        } else {
            return 0;
        }
        for (index = 0; index < continuation_count; index++) {
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

static int valid_relative_path(const char *path, int allow_root)
{
    const char *component;
    const char *cursor;

    if (path == NULL || path[0] == '\0' || path[0] == '/') {
        return 0;
    }
    if (allow_root && strcmp(path, ".") == 0) {
        return 1;
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

static int reserve(struct json_buffer *buffer, size_t additional)
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
    capacity = buffer->capacity == 0 ? 128 : buffer->capacity;
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

static int append_bytes(struct json_buffer *buffer, const void *bytes,
                        size_t length)
{
    if (reserve(buffer, length) < 0) {
        return -1;
    }
    memcpy(buffer->bytes + buffer->length, bytes, length);
    buffer->length += length;
    return 0;
}

static int append_literal(struct json_buffer *buffer, const char *literal)
{
    return append_bytes(buffer, literal, strlen(literal));
}

static int append_string(struct json_buffer *buffer, const char *value)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *cursor = (const unsigned char *)value;

    if (value == NULL || !valid_utf8(cursor) || append_literal(buffer, "\"") < 0) {
        errno = EILSEQ;
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

static int compare_strings(const void *left, const void *right)
{
    const char *const *left_string = left;
    const char *const *right_string = right;
    return strcmp(*left_string, *right_string);
}

static int append_declarations(struct json_buffer *buffer,
                               const char *const *items, size_t count)
{
    const char **sorted;
    size_t index;
    size_t emitted = 0;

    if (count > SIZE_MAX / sizeof(*sorted)) {
        errno = EOVERFLOW;
        return -1;
    }
    sorted = count == 0 ? NULL : malloc(count * sizeof(*sorted));
    if (count > 0 && sorted == NULL) {
        errno = ENOMEM;
        return -1;
    }
    for (index = 0; index < count; index++) {
        if (items == NULL || !valid_relative_path(items[index], 0) ||
            !valid_utf8((const unsigned char *)items[index])) {
            free(sorted);
            errno = EILSEQ;
            return -1;
        }
        sorted[index] = items[index];
    }
    if (count > 1) {
        qsort(sorted, count, sizeof(*sorted), compare_strings);
    }
    if (append_literal(buffer, "[") < 0) {
        free(sorted);
        return -1;
    }
    for (index = 0; index < count; index++) {
        if (index > 0 && strcmp(sorted[index], sorted[index - 1]) == 0) {
            continue;
        }
        if (emitted++ > 0 && append_literal(buffer, ",") < 0) {
            free(sorted);
            return -1;
        }
        if (append_string(buffer, sorted[index]) < 0) {
            free(sorted);
            return -1;
        }
    }
    free(sorted);
    return append_literal(buffer, "]");
}

static int append_identity_json(struct json_buffer *buffer,
                                const struct tm_command_identity *identity)
{
    size_t index;

    if (append_literal(buffer, "{\"argv\":[") < 0) {
        return -1;
    }
    for (index = 0; index < identity->argc; index++) {
        if (identity->argv == NULL || identity->argv[index] == NULL ||
            (index > 0 && append_literal(buffer, ",") < 0) ||
            append_string(buffer, identity->argv[index]) < 0) {
            return -1;
        }
    }
    if (append_literal(buffer,
                       "],\"execution_options\":{\"inputs\":") < 0 ||
        append_declarations(buffer, identity->inputs,
                            identity->input_count) < 0 ||
        append_literal(buffer, ",\"outputs\":") < 0 ||
        append_declarations(buffer, identity->outputs,
                            identity->output_count) < 0 ||
        append_literal(buffer, "},\"repository_id\":") < 0 ||
        append_string(buffer, identity->repository_id) < 0 ||
        append_literal(buffer, ",\"working_directory\":") < 0 ||
        append_string(buffer, identity->working_directory) < 0) {
        return -1;
    }
    return append_literal(buffer, "}");
}

int tm_command_fingerprint(const struct tm_command_identity *identity,
                           char output[72])
{
    static const unsigned char domain[] = "tm-command-v2";
    struct json_buffer buffer = {0};
    unsigned char *preimage;
    char digest[65];
    int result = -1;

    if (identity == NULL || output == NULL || identity->repository_id == NULL ||
        !valid_relative_path(identity->working_directory, 1) ||
        !valid_utf8((const unsigned char *)identity->repository_id) ||
        identity->argc == 0) {
        errno = EINVAL;
        return -1;
    }
    if (append_identity_json(&buffer, identity) < 0 ||
        buffer.length > SIZE_MAX - sizeof(domain)) {
        goto done;
    }
    preimage = malloc(sizeof(domain) + buffer.length);
    if (preimage == NULL) {
        errno = ENOMEM;
        goto done;
    }
    memcpy(preimage, domain, sizeof(domain));
    memcpy(preimage + sizeof(domain), buffer.bytes, buffer.length);
    if (tm_sha256_bytes(preimage, sizeof(domain) + buffer.length, digest) == 0) {
        memcpy(output, "sha256:", 7);
        memcpy(output + 7, digest, 65);
        result = 0;
    }
    free(preimage);

done:
    free(buffer.bytes);
    return result;
}
