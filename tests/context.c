#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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
    struct tm_json_value *host_context = parse(
        "{\"effective_uid\":1000,\"effective_gid\":1001,\"umask\":18,\"supplementary_groups\":[4,5],\"standard_descriptors\":{\"fd0\":{\"available\":1,\"file_type\":32768,\"tty\":1},\"fd1\":{\"available\":1,\"file_type\":4096,\"tty\":1},\"fd2\":{\"available\":1,\"file_type\":4096,\"tty\":1}},\"kernel_release\":\"6.8\"}");
    struct tm_json_value *profile_context = NULL, *v1_context = NULL;
    struct tm_json_value *unknown_context = NULL;
    char first[72], second[72], changed[72];
    int status = 1;
    struct tm_json_value *captured = NULL;
    const struct tm_json_value *profile_descriptors, *projected_fd0;
    const struct tm_json_value *projected_fd1, *projected_groups, *v1_fd0;

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
        host_context == NULL ||
        tm_context_project_bubblewrap(host_context,
            "bubblewrap-linux-x86_64-v2", &profile_context) < 0 ||
        tm_context_project_bubblewrap(host_context,
            "bubblewrap-linux-x86_64-v1", &v1_context) < 0 ||
        tm_context_project_bubblewrap(host_context, "unknown",
                                      &unknown_context) == 0 ||
        tm_context_capture_linux(&captured) < 0 ||
        tm_json_typeof(captured) != TM_JSON_OBJECT ||
        tm_json_object_get(captured, "kernel_release") == NULL ||
        tm_json_typeof(tm_json_object_get(captured,
                            "cpu_capabilities")) != TM_JSON_ARRAY ||
        tm_json_size(tm_json_object_get(captured,
                            "cpu_capabilities")) == 0 ||
        tm_json_object_get(captured, "resource_limits") == NULL ||
        tm_json_object_get(captured, "supplementary_groups") == NULL) {
        fprintf(stderr, "context fingerprint vector or capture failed\n");
        goto done;
    }
    profile_descriptors = tm_json_object_get(profile_context,
                                               "standard_descriptors");
    projected_fd0 = tm_json_object_get(profile_descriptors, "fd0");
    projected_fd1 = tm_json_object_get(profile_descriptors, "fd1");
    projected_groups = tm_json_object_get(profile_context,
                                           "supplementary_groups");
    v1_fd0 = tm_json_object_get(
        tm_json_object_get(v1_context, "standard_descriptors"), "fd0");
    if (tm_json_integer_value(tm_json_object_get(profile_context,
            "effective_uid")) != 0 ||
        tm_json_integer_value(tm_json_object_get(profile_context,
            "effective_gid")) != 0 ||
        tm_json_integer_value(tm_json_object_get(profile_context,
            "umask")) != 022 ||
        tm_json_integer_value(tm_json_object_get(projected_fd0,
            "available")) != 1 ||
        tm_json_integer_value(tm_json_object_get(projected_fd0,
            "file_type")) != (uint64_t)S_IFCHR ||
        tm_json_integer_value(tm_json_object_get(projected_fd0,
            "tty")) != 0 ||
        tm_json_integer_value(tm_json_object_get(projected_fd1,
            "tty")) != 1 ||
        tm_json_size(projected_groups) != 2 ||
        tm_json_integer_value(tm_json_object_get(v1_context,
            "effective_uid")) != 1000 ||
        tm_json_integer_value(tm_json_object_get(v1_context,
            "umask")) != 022 ||
        tm_json_integer_value(tm_json_object_get(v1_fd0, "tty")) != 0) {
        fprintf(stderr, "Bubblewrap context projection failed\n");
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
    tm_json_free(host_context);
    tm_json_free(profile_context);
    tm_json_free(v1_context);
    tm_json_free(unknown_context);
    tm_json_free(captured);
    return status;
}
