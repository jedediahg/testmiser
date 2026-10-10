#ifndef TM_JSON_H
#define TM_JSON_H

#include <stddef.h>
#include <stdint.h>

enum tm_json_type {
    TM_JSON_NULL, TM_JSON_BOOLEAN, TM_JSON_INTEGER,
    TM_JSON_STRING, TM_JSON_ARRAY, TM_JSON_OBJECT
};
struct tm_json_value;

struct tm_json_value *tm_json_new_null(void);
struct tm_json_value *tm_json_new_boolean(int value);
struct tm_json_value *tm_json_new_integer(uint64_t value);
struct tm_json_value *tm_json_new_string(const char *value);
struct tm_json_value *tm_json_new_array(void);
struct tm_json_value *tm_json_new_object(void);
int tm_json_array_append(struct tm_json_value *array, struct tm_json_value *value);
int tm_json_object_set(struct tm_json_value *object, const char *key,
                       struct tm_json_value *value);
enum tm_json_type tm_json_typeof(const struct tm_json_value *value);
const struct tm_json_value *tm_json_object_get(
    const struct tm_json_value *object, const char *key);
const char *tm_json_object_key_at(const struct tm_json_value *object,
                                  size_t index);
const struct tm_json_value *tm_json_object_value_at(
    const struct tm_json_value *object, size_t index);
const struct tm_json_value *tm_json_array_get(
    const struct tm_json_value *array, size_t index);
size_t tm_json_size(const struct tm_json_value *value);
const char *tm_json_string_value(const struct tm_json_value *value);
uint64_t tm_json_integer_value(const struct tm_json_value *value);
int tm_json_boolean_value(const struct tm_json_value *value);
void tm_json_free(struct tm_json_value *value);

/* Strict bounded JSON parser and RFC 8785 canonical UTF-8 serializer. */
int tm_json_parse(const unsigned char *data, size_t length,
                  struct tm_json_value **output);
int tm_json_canonicalize(const struct tm_json_value *value,
                         unsigned char **output, size_t *length);

#endif
