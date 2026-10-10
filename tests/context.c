#include <stdio.h>
#include <string.h>

#include "tm/context.h"

static struct tm_json_value *parse(const char *text)
{
    struct tm_json_value *value = NULL;
    if (tm_json_parse((const unsigned char *)text, strlen(text), &value) < 0)
        return NULL;
    return value;
}

int main(void)
{
    struct tm_json_value *environment = parse(
        "{\"PATH\":\"/usr/bin:/bin\",\"LANG\":\"C\"}");
    struct tm_json_value *reordered = parse(
        "{\"LANG\":\"C\",\"PATH\":\"/usr/bin:/bin\"}");
    struct tm_json_value *empty = parse(
        "{\"LANG\":\"C\",\"PATH\":\"\"}");
    struct tm_json_value *bad_env = parse("{\"PATH\":1}");
    struct tm_json_value *bad_context = parse("[]");
    struct tm_json_value *context = parse(
        "{\"kernel\":\"6.8\",\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"backend\":\"bwrap-v1\"}");
    char first[72], second[72], changed[72];
    int status = 1;
    struct tm_json_value *captured = NULL;

    if (environment == NULL || reordered == NULL || empty == NULL ||
        bad_env == NULL || bad_context == NULL || context == NULL ||
        tm_context_fingerprint(environment, context, first) < 0 ||
        strcmp(first, "sha256:297cafe259f43f2044442d7c0ece637338dce20763b8bf22f07db88ace0e947b") != 0 ||
        tm_context_fingerprint(reordered, context, second) < 0 ||
        strcmp(first, second) != 0 ||
        tm_context_fingerprint(empty, context, changed) < 0 ||
        strcmp(first, changed) == 0 ||
        tm_context_fingerprint(bad_env, context, changed) == 0 ||
        tm_context_fingerprint(environment, bad_context, changed) == 0 ||
        tm_context_capture_linux(&captured) < 0 ||
        tm_json_typeof(captured) != TM_JSON_OBJECT ||
        tm_json_object_get(captured, "kernel_release") == NULL ||
        tm_json_object_get(captured, "cpu_flags") == NULL ||
        tm_json_object_get(captured, "resource_limits") == NULL ||
        tm_json_object_get(captured, "supplementary_groups") == NULL) {
        fprintf(stderr, "context fingerprint vector or validation failed\n");
        goto done;
    }
    status = 0;
done:
    tm_json_free(environment);
    tm_json_free(reordered);
    tm_json_free(empty);
    tm_json_free(bad_env);
    tm_json_free(bad_context);
    tm_json_free(context);
    tm_json_free(captured);
    return status;
}
