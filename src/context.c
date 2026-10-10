#define _GNU_SOURCE

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "tm/context.h"
#include "tm/digest.h"

static int put_string(struct tm_json_value *object, const char *key,
                      const char *value)
{
    struct tm_json_value *json = tm_json_new_string(value);
    if (json == NULL) return -1;
    if (tm_json_object_set(object, key, json) < 0) {
        tm_json_free(json);
        return -1;
    }
    return 0;
}

static int put_integer(struct tm_json_value *object, const char *key,
                       uint64_t value)
{
    struct tm_json_value *json = tm_json_new_integer(value);
    if (json == NULL) return -1;
    if (tm_json_object_set(object, key, json) < 0) {
        tm_json_free(json);
        return -1;
    }
    return 0;
}

static int put_limit(struct tm_json_value *object, const char *key,
                     rlim_t value)
{
    struct tm_json_value *json;
    if (value == RLIM_INFINITY) return put_string(object, key, "infinity");
    if ((uintmax_t)value > UINT64_MAX) { errno = EOVERFLOW; return -1; }
    json = tm_json_new_integer((uint64_t)value);
    if (json == NULL) return -1;
    if (tm_json_object_set(object, key, json) < 0) {
        tm_json_free(json);
        return -1;
    }
    return 0;
}

static int add_limit(struct tm_json_value *limits, const char *name,
                     int resource)
{
    struct rlimit limit;
    char soft_key[64], hard_key[64];
    int first = snprintf(soft_key, sizeof(soft_key), "%s_soft", name);
    int second = snprintf(hard_key, sizeof(hard_key), "%s_hard", name);
    if (first < 0 || second < 0 || (size_t)first >= sizeof(soft_key) ||
        (size_t)second >= sizeof(hard_key) || getrlimit(resource, &limit) < 0)
        return -1;
    return put_limit(limits, soft_key, limit.rlim_cur) < 0 ||
           put_limit(limits, hard_key, limit.rlim_max) < 0 ? -1 : 0;
}

static int compare_gid(const void *left, const void *right)
{
    gid_t a = *(const gid_t *)left, b = *(const gid_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

int tm_context_capture_linux(struct tm_json_value **execution_context)
{
    struct tm_json_value *context = NULL, *limits = NULL, *groups_json = NULL;
    struct tm_json_value *affinity_json = NULL, *descriptors = NULL;
    struct utsname name;
    cpu_set_t cpus;
    gid_t *groups = NULL;
    int group_count, i, status = -1;
    mode_t mask;
    const char *cpu_flags = NULL;
    char *cpu_info = NULL;
    size_t cpu_info_capacity = 0;
    FILE *cpu_file = NULL;
    static const struct { const char *name; int resource; } resources[] = {
        {"as", RLIMIT_AS}, {"core", RLIMIT_CORE}, {"cpu", RLIMIT_CPU},
        {"data", RLIMIT_DATA}, {"fsize", RLIMIT_FSIZE},
        {"memlock", RLIMIT_MEMLOCK}, {"msgqueue", RLIMIT_MSGQUEUE},
        {"nice", RLIMIT_NICE}, {"nofile", RLIMIT_NOFILE},
        {"nproc", RLIMIT_NPROC}, {"rss", RLIMIT_RSS},
        {"rtprio", RLIMIT_RTPRIO}, {"rttime", RLIMIT_RTTIME},
        {"sigpending", RLIMIT_SIGPENDING}, {"stack", RLIMIT_STACK}
    };
    size_t index;

    if (execution_context == NULL) { errno = EINVAL; return -1; }
    *execution_context = NULL;
    if (uname(&name) < 0 || strcmp(name.sysname, "Linux") != 0 ||
        strcmp(name.machine, "x86_64") != 0) {
        errno = ENOTSUP;
        return -1;
    }
    context = tm_json_new_object();
    limits = tm_json_new_object();
    groups_json = tm_json_new_array();
    affinity_json = tm_json_new_array();
    descriptors = tm_json_new_object();
    if (context == NULL || limits == NULL || groups_json == NULL ||
        affinity_json == NULL || descriptors == NULL) goto done;

    if (put_string(context, "os", name.sysname) < 0 ||
        put_string(context, "architecture", name.machine) < 0 ||
        put_string(context, "abi", "linux-x86_64-elf64") < 0 ||
        put_string(context, "kernel_release", name.release) < 0 ||
        put_string(context, "kernel_version", name.version) < 0 ||
        put_integer(context, "effective_uid", (uint64_t)geteuid()) < 0 ||
        put_integer(context, "effective_gid", (uint64_t)getegid()) < 0)
        goto done;

    group_count = getgroups(0, NULL);
    if (group_count < 0) goto done;
    groups = calloc(group_count == 0 ? 1U : (size_t)group_count,
                    sizeof(*groups));
    if (groups == NULL) goto done;
    if (group_count > 0 && getgroups(group_count, groups) != group_count)
        goto done;
    qsort(groups, (size_t)group_count, sizeof(*groups), compare_gid);
    for (i = 0; i < group_count; i++) {
        struct tm_json_value *group = tm_json_new_integer((uint64_t)groups[i]);
        if (group == NULL || tm_json_array_append(groups_json, group) < 0) {
            tm_json_free(group);
            goto done;
        }
    }
    if (tm_json_object_set(context, "supplementary_groups", groups_json) < 0)
        goto done;
    groups_json = NULL;

    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus) < 0) goto done;
    for (i = 0; i < CPU_SETSIZE; i++) if (CPU_ISSET(i, &cpus)) {
        struct tm_json_value *cpu = tm_json_new_integer((uint64_t)i);
        if (cpu == NULL || tm_json_array_append(affinity_json, cpu) < 0) {
            tm_json_free(cpu);
            goto done;
        }
    }
    if (tm_json_size(affinity_json) == 0 ||
        tm_json_object_set(context, "cpu_affinity", affinity_json) < 0)
        goto done;
    affinity_json = NULL;

    cpu_file = fopen("/proc/cpuinfo", "r");
    if (cpu_file == NULL) goto done;
    while (getline(&cpu_info, &cpu_info_capacity, cpu_file) >= 0) {
        char *value;
        if (strncmp(cpu_info, "flags", 5) != 0) continue;
        value = strchr(cpu_info, ':');
        if (value == NULL) continue;
        value++;
        while (*value == ' ' || *value == '\t') value++;
        value[strcspn(value, "\r\n")] = '\0';
        cpu_flags = value;
        break;
    }
    if (cpu_flags == NULL || put_string(context, "cpu_flags", cpu_flags) < 0)
        goto done;

    for (index = 0; index < sizeof(resources) / sizeof(resources[0]); index++)
        if (add_limit(limits, resources[index].name,
                      resources[index].resource) < 0) goto done;
    if (tm_json_object_set(context, "resource_limits", limits) < 0) goto done;
    limits = NULL;

    mask = umask(0);
    (void)umask(mask);
    if (put_integer(context, "umask", (uint64_t)mask) < 0) goto done;
    for (i = 0; i < 3; i++) {
        char key[16];
        struct stat st;
        struct tm_json_value *descriptor = tm_json_new_object();
        int n = snprintf(key, sizeof(key), "fd%d", i);
        int available = fstat(i, &st) == 0;
        if (descriptor == NULL || n < 0 || (size_t)n >= sizeof(key) ||
            put_integer(descriptor, "available", (uint64_t)available) < 0 ||
            (available && put_integer(descriptor, "file_type",
                (uint64_t)(st.st_mode & S_IFMT)) < 0) ||
            put_integer(descriptor, "tty", isatty(i) == 1) < 0 ||
            tm_json_object_set(descriptors, key, descriptor) < 0) {
            tm_json_free(descriptor);
            goto done;
        }
    }
    if (tm_json_object_set(context, "standard_descriptors", descriptors) < 0)
        goto done;
    descriptors = NULL;
    *execution_context = context;
    context = NULL;
    status = 0;
done:
    if (cpu_file != NULL) fclose(cpu_file);
    free(cpu_info);
    free(groups);
    tm_json_free(descriptors);
    tm_json_free(affinity_json);
    tm_json_free(groups_json);
    tm_json_free(limits);
    tm_json_free(context);
    return status;
}

static int add_length(size_t *total, size_t length)
{
    if (length > SIZE_MAX - *total) return -1;
    *total += length;
    return 0;
}

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
    size_t offset = 0;
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
    identity_length = 0;
    if (add_length(&identity_length, prefix_length) < 0 ||
        add_length(&identity_length, object_prefix_length) < 0 ||
        add_length(&identity_length, environment_length) < 0 ||
        add_length(&identity_length, separator_length) < 0 ||
        add_length(&identity_length, context_length) < 0 ||
        add_length(&identity_length, 1) < 0) {
        errno = EOVERFLOW;
        goto done;
    }
    identity = malloc(identity_length);
    if (identity == NULL) goto done;
    memcpy(identity + offset, prefix, prefix_length); offset += prefix_length;
    memcpy(identity + offset, object_prefix, object_prefix_length);
    offset += object_prefix_length;
    memcpy(identity + offset, environment_json, environment_length);
    offset += environment_length;
    memcpy(identity + offset, separator, separator_length);
    offset += separator_length;
    memcpy(identity + offset, context_json, context_length);
    offset += context_length;
    identity[offset++] = '}';
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
