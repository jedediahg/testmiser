#define _GNU_SOURCE

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tm/backend.h"
#include "tm/digest.h"
#include "tm/observer.h"
#include "tm/profile.h"
#include "tm/repo.h"
#include "tm/runtime.h"
#include "tm/snapshot.h"

#ifndef TM_TEST_BWRAP
#define BWRAP_PATH "/usr/bin/bwrap"
#else
#define BWRAP_PATH TM_TEST_BWRAP
#endif
#define GUEST_WORKSPACE "/workspace"
#define GUEST_METADATA "/workspace/.tm"

#ifndef TM_TEST_BWRAP
static int trusted_executable_directories(const char *executable_path)
{
    char *parent = strdup(executable_path);
    int trusted = 0;
    if (parent == NULL) return -1;
    for (;;) {
        char *separator = strrchr(parent, '/');
        struct stat status;
        int descriptor;
        if (separator == NULL) { errno = EINVAL; break; }
        if (separator == parent) separator[1] = '\0';
        else *separator = '\0';
        descriptor = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                  O_NOFOLLOW);
        if (descriptor < 0) break;
        if (fstat(descriptor, &status) < 0) {
            int saved = errno;
            close(descriptor);
            errno = saved;
            break;
        }
        if (!S_ISDIR(status.st_mode) || status.st_uid != 0) {
            close(descriptor);
            errno = EPERM;
            break;
        }
        if ((status.st_mode & 0022) != 0) {
            close(descriptor);
            errno = EPERM;
            break;
        }
        close(descriptor);
        if (strcmp(parent, "/") == 0) {
            trusted = 1;
            break;
        }
    }
    free(parent);
    return trusted ? 0 : -1;
}
#endif

int tm_backend_executable_identity(char **resolved_path, char digest[72])
{
    struct stat before, after;
    char *path;
    char hex[65];
    int saved;
    if (resolved_path == NULL || digest == NULL) {
        errno = EINVAL;
        return -1;
    }
    *resolved_path = NULL;
    path = realpath(BWRAP_PATH, NULL);
    if (path == NULL) return -1;
    if (lstat(path, &before) < 0) {
        saved = errno;
        free(path);
        errno = saved;
        return -1;
    }
    if (!S_ISREG(before.st_mode)) {
        free(path);
        errno = EINVAL;
        return -1;
    }
#ifndef TM_TEST_BWRAP
    if (geteuid() == 0 ||
        (before.st_mode & (S_ISUID | S_ISGID)) != 0 ||
        before.st_uid != 0 || (before.st_mode & 0022) != 0) {
        free(path);
        errno = EPERM;
        return -1;
    }
    if (trusted_executable_directories(path) < 0) {
        saved = errno;
        free(path);
        errno = saved;
        return -1;
    }
#endif
    errno = 0;
    if (tm_sha256_file(path, hex) < 0 || lstat(path, &after) < 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
        before.st_gid != after.st_gid || before.st_size != after.st_size ||
        before.st_nlink != after.st_nlink ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec ||
        before.st_ctim.tv_nsec != after.st_ctim.tv_nsec) {
        saved = errno == 0 ? EBUSY : errno;
        free(path);
        errno = saved;
        return -1;
    }
    memcpy(digest, "sha256:", 7);
    memcpy(digest + 7, hex, sizeof(hex));
    *resolved_path = path;
    return 0;
}

static int child_descriptor_is_preserved(const int *preserved,
                                         size_t preserved_count,
                                         int descriptor)
{
    size_t index;
    for (index = 0; index < preserved_count; index++)
        if (preserved[index] == descriptor) return 1;
    return 0;
}

static int close_child_descriptors(const int *preserved,
                                   size_t preserved_count)
{
    size_t preserved_index;
    for (preserved_index = 0; preserved_index < preserved_count;
         preserved_index++) {
        int flags = fcntl(preserved[preserved_index], F_GETFD);
        if (flags < 0 || fcntl(preserved[preserved_index], F_SETFD,
                               flags & ~FD_CLOEXEC) < 0) return -1;
    }
    {
        DIR *directory = opendir("/proc/self/fd");
        if (directory != NULL) {
            struct dirent *entry;
            int scan_descriptor = dirfd(directory), failed = 0;
            for (;;) {
                char *end;
                long descriptor;
                errno = 0;
                entry = readdir(directory);
                if (entry == NULL) {
                    if (errno != 0) failed = 1;
                    break;
                }
                descriptor = strtol(entry->d_name, &end, 10);
                if (*entry->d_name == '\0' || *end != '\0' ||
                    descriptor <= STDERR_FILENO || descriptor == scan_descriptor ||
                    descriptor > INT_MAX || child_descriptor_is_preserved(
                        preserved, preserved_count, (int)descriptor))
                    continue;
                (void)close((int)descriptor);
            }
            if (closedir(directory) < 0) failed = 1;
            if (!failed) return 0;
        }
    }
    if (preserved_count != 0) { errno = ENOTSUP; return -1; }
    {
        struct rlimit limit;
        rlim_t upper;
        rlim_t descriptor;
        if (getrlimit(RLIMIT_NOFILE, &limit) < 0) return -1;
        upper = limit.rlim_cur;
        if (upper == RLIM_INFINITY) {
            long configured = sysconf(_SC_OPEN_MAX);
            if (configured < 0) return -1;
            upper = (rlim_t)configured;
        }
        for (descriptor = 3; descriptor < upper && descriptor <= INT_MAX;
             descriptor++)
            (void)close((int)descriptor);
    }
    return 0;
}

struct argument_vector {
    char **items;
    size_t count;
    size_t capacity;
    int *preserved_fds;
    size_t preserved_fd_count;
};

static int push_argument(struct argument_vector *arguments,
                         const char *value);

static int init_arguments(struct argument_vector *arguments, size_t capacity)
{
    if (capacity < 2 || capacity > SIZE_MAX / sizeof(*arguments->items)) {
        errno = EOVERFLOW;
        return -1;
    }
    arguments->items = calloc(capacity, sizeof(*arguments->items));
    if (arguments->items == NULL) return -1;
    arguments->preserved_fds = calloc(capacity,
                                      sizeof(*arguments->preserved_fds));
    if (arguments->preserved_fds == NULL) {
        free(arguments->items);
        arguments->items = NULL;
        return -1;
    }
    arguments->capacity = capacity;
    return 0;
}

static void free_arguments(struct argument_vector *arguments)
{
    size_t index;
    for (index = 0; index < arguments->count; index++)
        free(arguments->items[index]);
    for (index = 0; index < arguments->preserved_fd_count; index++)
        close(arguments->preserved_fds[index]);
    free(arguments->items);
    free(arguments->preserved_fds);
    memset(arguments, 0, sizeof(*arguments));
}

static int push_readonly_bind_fd(struct argument_vector *arguments,
                                 int descriptor, const char *guest_path)
{
    char descriptor_text[32];
    int length;
    if (arguments->preserved_fd_count >= arguments->capacity) {
        errno = E2BIG;
        return -1;
    }
    length = snprintf(descriptor_text, sizeof(descriptor_text), "%d",
                      descriptor);
    if (length < 0 || (size_t)length >= sizeof(descriptor_text)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (push_argument(arguments, "--ro-bind-fd") < 0 ||
        push_argument(arguments, descriptor_text) < 0 ||
        push_argument(arguments, guest_path) < 0) return -1;
    arguments->preserved_fds[arguments->preserved_fd_count++] = descriptor;
    return 0;
}

static int descriptor_above_stdio(int descriptor)
{
    int copy;
    if (descriptor >= STDERR_FILENO + 1) return descriptor;
    copy = fcntl(descriptor, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (copy < 0) {
        int saved = errno;
        close(descriptor);
        errno = saved;
        return -1;
    }
    close(descriptor);
    return copy;
}

static int open_directory_without_symlinks(const char *path)
{
    int current;
    const char *part;
    if (path == NULL || path[0] != '/') { errno = EINVAL; return -1; }
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) return -1;
    part = path;
    while (*part == '/') part++;
    while (*part != '\0') {
        const char *slash = strchr(part, '/');
        size_t length = slash == NULL ? strlen(part) :
                                       (size_t)(slash - part);
        char *component = strndup(part, length);
        struct stat status;
        int next;
        if (component == NULL) goto fail;
        next = openat(current, component,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        free(component);
        if (next < 0) goto fail;
        if (fstat(next, &status) < 0) {
            int saved = errno;
            close(next);
            errno = saved;
            goto fail;
        }
        if (!S_ISDIR(status.st_mode)) {
            close(next);
            errno = ENOTDIR;
            goto fail;
        }
        close(current);
        current = next;
        if (slash == NULL) break;
        part = slash + 1;
        while (*part == '/') part++;
    }
    return descriptor_above_stdio(current);
fail:
    {
        int saved = errno;
        close(current);
        errno = saved;
    }
    return -1;
}

static int push_argument(struct argument_vector *arguments, const char *value)
{
    char *copy;
    if (arguments->items == NULL || arguments->count + 1 >= arguments->capacity) {
        errno = E2BIG;
        return -1;
    }
    copy = strdup(value);
    if (copy == NULL) return -1;
    arguments->items[arguments->count++] = copy;
    arguments->items[arguments->count] = NULL;
    return 0;
}

static int push_pair(struct argument_vector *arguments, const char *option,
                     const char *value)
{
    return push_argument(arguments, option) < 0 ||
           push_argument(arguments, value) < 0 ? -1 : 0;
}

static int push_output_mount(struct argument_vector *arguments, int *descriptor,
                             const char *path)
{
    char *guest_path;
    size_t length = strlen(path) + sizeof(GUEST_WORKSPACE) + 1;
    char descriptor_text[32];
    int result;
    guest_path = malloc(length);
    if (guest_path == NULL) return -1;
    if (snprintf(guest_path, length, "%s/%s", GUEST_WORKSPACE, path) < 0) {
        free(guest_path);
        errno = EIO;
        return -1;
    }
    if (descriptor == NULL || *descriptor < 0 ||
        arguments->preserved_fd_count >= arguments->capacity) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(descriptor_text, sizeof(descriptor_text), "%d",
                 *descriptor) >= (int)sizeof(descriptor_text)) {
        free(guest_path);
        errno = EOVERFLOW;
        return -1;
    }
    result = push_argument(arguments, "--bind-fd") < 0 ||
             push_argument(arguments, descriptor_text) < 0 ||
             push_argument(arguments, guest_path) < 0 ? -1 : 0;
    if (result == 0) {
        arguments->preserved_fds[arguments->preserved_fd_count++] = *descriptor;
        *descriptor = -1;
    }
    free(guest_path);
    return result;
}

static int open_or_create_output_directory(int root_fd, const char *path)
{
    char *copy = strdup(path);
    char *component, *save = NULL;
    int current = dup(root_fd);
    if (copy == NULL || current < 0) {
        free(copy);
        if (current >= 0) close(current);
        return -1;
    }
    for (component = strtok_r(copy, "/", &save); component != NULL;
         component = strtok_r(NULL, "/", &save)) {
        int next;
        if (mkdirat(current, component, 0700) < 0 && errno != EEXIST)
            goto fail;
        next = openat(current, component, O_RDONLY | O_DIRECTORY |
                       O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) goto fail;
        close(current);
        current = next;
    }
    free(copy);
    return current;
fail:
    {
        int saved = errno;
        close(current);
        free(copy);
        errno = saved;
    }
    return -1;
}

static int remove_output_stage_contents(int directory_fd, unsigned int depth);

static int create_output_stage(const char *const *roots, size_t root_count,
                               char **stage_path, int *stage_fd,
                               int **output_fds)
{
    char template[] = "/tmp/tm-output-stage-XXXXXX";
    size_t index;
    int *descriptors;
    if (roots == NULL || root_count == 0 || stage_path == NULL ||
        stage_fd == NULL || output_fds == NULL) { errno = EINVAL; return -1; }
    *stage_path = NULL;
    *stage_fd = -1;
    *output_fds = NULL;
    if (tm_output_roots_validate(roots, root_count) < 0 ||
        root_count > SIZE_MAX / sizeof(*descriptors)) return -1;
    descriptors = malloc(root_count * sizeof(*descriptors));
    if (descriptors == NULL) return -1;
    for (index = 0; index < root_count; index++) descriptors[index] = -1;
    *stage_path = strdup(template);
    if (*stage_path == NULL || mkdtemp(*stage_path) == NULL) goto fail;
    *stage_fd = open(*stage_path,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (*stage_fd < 0) goto fail;
    for (index = 0; index < root_count; index++) {
        int directory = open_or_create_output_directory(*stage_fd, roots[index]);
        if (directory < 0) goto fail;
        descriptors[index] = directory;
    }
    *output_fds = descriptors;
    return 0;
fail:
    {
        int saved = errno;
        for (index = 0; index < root_count; index++)
            if (descriptors[index] >= 0) close(descriptors[index]);
        free(descriptors);
        if (*stage_fd >= 0) {
            (void)remove_output_stage_contents(*stage_fd, 0);
            close(*stage_fd);
        }
        if (*stage_path != NULL) {
            (void)rmdir(*stage_path);
            free(*stage_path);
            *stage_path = NULL;
        }
        *stage_fd = -1;
        errno = saved;
    }
    return -1;
}

static int remove_output_stage_contents(int directory_fd, unsigned int depth)
{
    DIR *directory;
    int duplicate, result = 0;
    if (depth > 128) { errno = ELOOP; return -1; }
    duplicate = dup(directory_fd);
    if (duplicate < 0) return -1;
    directory = fdopendir(duplicate);
    if (directory == NULL) { close(duplicate); return -1; }
    for (;;) {
        struct dirent *entry;
        struct stat status;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) result = -1;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        if (fstatat(directory_fd, entry->d_name, &status,
                    AT_SYMLINK_NOFOLLOW) < 0) { result = -1; break; }
        if (S_ISDIR(status.st_mode)) {
            int child = openat(directory_fd, entry->d_name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || remove_output_stage_contents(child, depth + 1) < 0) {
                int saved = errno;
                if (child >= 0) close(child);
                errno = saved;
                result = -1;
                break;
            }
            close(child);
            if (unlinkat(directory_fd, entry->d_name, AT_REMOVEDIR) < 0) {
                result = -1;
                break;
            }
        } else if (unlinkat(directory_fd, entry->d_name, 0) < 0) {
            result = -1;
            break;
        }
    }
    closedir(directory);
    return result;
}

static int push_input_mount(struct argument_vector *arguments,
                            const struct tm_snapshot *snapshot,
                            size_t index, const char *path)
{
    size_t guest_length = strlen(GUEST_WORKSPACE) + strlen(path) + 2;
    char *guest = malloc(guest_length);
    int descriptor, result;
    if (guest == NULL) return -1;
    if (snprintf(guest, guest_length, "%s/%s", GUEST_WORKSPACE, path) < 0) {
        free(guest);
        errno = EIO;
        return -1;
    }
    descriptor = tm_snapshot_open_root(snapshot, index);
    if (descriptor < 0) { free(guest); return -1; }
    result = push_readonly_bind_fd(arguments, descriptor, guest);
    if (result < 0) close(descriptor);
    free(guest);
    return result;
}

static int input_parent_was_created(const struct tm_profile *profile,
                                    size_t root_index, const char *path,
                                    size_t prefix_length)
{
    size_t previous;
    for (previous = 0; previous < root_index; previous++) {
        const char *prior = tm_profile_input_root(profile, previous);
        if (strncmp(prior, path, prefix_length) == 0 &&
            (prior[prefix_length] == '\0' || prior[prefix_length] == '/'))
            return 1;
    }
    return 0;
}

static int push_input_parent_directories(struct argument_vector *arguments,
                                         const struct tm_profile *profile)
{
    size_t root_index;
    for (root_index = 0; root_index < tm_profile_input_root_count(profile);
         root_index++) {
        const char *path = tm_profile_input_root(profile, root_index);
        const char *slash = path;
        while ((slash = strchr(slash, '/')) != NULL) {
            size_t prefix_length = (size_t)(slash - path);
            size_t guest_length = strlen(GUEST_WORKSPACE) + prefix_length + 2;
            char *guest;
            int result;
            if (!input_parent_was_created(profile, root_index, path,
                                          prefix_length)) {
                guest = malloc(guest_length);
                if (guest == NULL) return -1;
                (void)snprintf(guest, guest_length, "%s/%.*s",
                               GUEST_WORKSPACE, (int)prefix_length, path);
                result = push_pair(arguments, "--dir", guest);
                free(guest);
                if (result < 0) return -1;
            }
            slash++;
        }
    }
    return 0;
}

static int push_output_parent_directories(struct argument_vector *arguments,
                                          const char *const *roots,
                                          size_t root_count)
{
    size_t index;
    for (index = 0; index < root_count; index++) {
        const char *path = roots[index], *slash = path;
        while ((slash = strchr(slash, '/')) != NULL) {
            size_t prefix_length = (size_t)(slash - path);
            size_t guest_length = strlen(GUEST_WORKSPACE) + prefix_length + 2;
            char *guest = malloc(guest_length);
            int pushed;
            if (guest == NULL) return -1;
            (void)snprintf(guest, guest_length, "%s/%.*s",
                           GUEST_WORKSPACE, (int)prefix_length, path);
            pushed = push_pair(arguments, "--dir", guest);
            free(guest);
            if (pushed < 0) return -1;
            slash++;
        }
    }
    return 0;
}

static int digest_profile_runtime(int runtime_fd,
                                  const struct tm_profile *profile,
                                  char output[72])
{
#ifdef TM_TEST_BWRAP
    (void)profile;
    return tm_runtime_tree_digest_fd(runtime_fd, output);
#else
    size_t count = tm_profile_scratch_root_count(profile), index;
    const char **writable_roots = NULL;
    int result;
    if (count != 0) {
        writable_roots = calloc(count, sizeof(*writable_roots));
        if (writable_roots == NULL) return -1;
        for (index = 0; index < count; index++)
            writable_roots[index] = tm_profile_scratch_root(profile, index);
    }
    result = tm_runtime_tree_digest_readonly_fd(runtime_fd, writable_roots,
                                                count, output);
    free(writable_roots);
    return result;
#endif
}

static int scratch_contains(const struct tm_profile *profile,
                            const char *path)
{
    size_t index;
    for (index = 0; index < tm_profile_scratch_root_count(profile); index++)
        if (strcmp(tm_profile_scratch_root(profile, index), path) == 0)
            return 1;
    return 0;
}

static int profile_value(const struct tm_profile *profile, const char *name,
                         const char **value)
{
    size_t index;
    for (index = 0; index < tm_profile_environment_count(profile); index++) {
        if (strcmp(tm_profile_environment_name(profile, index), name) == 0) {
            *value = tm_profile_environment_value(profile, index);
            return 1;
        }
    }
    *value = NULL;
    return 0;
}

static int add_environment(struct argument_vector *arguments,
                           const struct tm_profile *profile)
{
    const char *home, *tmpdir, *path;
    const char *default_scratch;
    size_t index;
    if (tm_profile_scratch_root_count(profile) == 0) return 0;
    default_scratch = tm_profile_scratch_root(profile, 0);
    if (!profile_value(profile, "HOME", &home)) home = default_scratch;
    if (!profile_value(profile, "TMPDIR", &tmpdir)) tmpdir = default_scratch;
    if (!scratch_contains(profile, home) || !scratch_contains(profile, tmpdir))
        return 0;

    if (push_argument(arguments, "--clearenv") < 0) return -1;
    for (index = 0; index < tm_profile_environment_count(profile); index++) {
        if (push_argument(arguments, "--setenv") < 0 ||
            push_argument(arguments,
                          tm_profile_environment_name(profile, index)) < 0 ||
            push_argument(arguments,
                          tm_profile_environment_value(profile, index)) < 0)
            return -1;
    }
    if (profile_value(profile, "HOME", &home) == 0 &&
        (push_argument(arguments, "--setenv") < 0 ||
         push_argument(arguments, "HOME") < 0 ||
         push_argument(arguments, default_scratch) < 0)) return -1;
    if (profile_value(profile, "TMPDIR", &tmpdir) == 0 &&
        (push_argument(arguments, "--setenv") < 0 ||
         push_argument(arguments, "TMPDIR") < 0 ||
         push_argument(arguments, default_scratch) < 0)) return -1;
    if (profile_value(profile, "PATH", &path) == 0 &&
        (push_argument(arguments, "--setenv") < 0 ||
         push_argument(arguments, "PATH") < 0 ||
         push_argument(arguments, "/usr/bin:/bin") < 0)) return -1;
    return 1;
}

static int build_arguments(struct argument_vector *arguments,
                           const struct tm_profile *profile,
                           const char *runtime_root,
                           const struct tm_snapshot *snapshot,
                           const char *working_directory,
                           const char *const *output_roots,
                           int *output_fds,
                           size_t output_root_count,
                           char **command)
{
    char *guest_cwd = NULL;
    char *bubblewrap_path = NULL;
    char bubblewrap_digest[72];
    const char *relative_cwd = working_directory;
    size_t index, length, command_count = 0, capacity;
    int environment_added;

    while (command[command_count] != NULL) {
        if (command_count == SIZE_MAX) { errno = EOVERFLOW; return -1; }
        command_count++;
    }
    capacity = 64;
    if (tm_profile_environment_count(profile) > (SIZE_MAX - capacity) / 3) {
        errno = EOVERFLOW; return -1;
    }
    capacity += 3 * tm_profile_environment_count(profile);
    if (capacity > SIZE_MAX - 4) { errno = EOVERFLOW; return -1; }
    capacity += 4;
    for (index = 0; index < tm_profile_input_root_count(profile); index++) {
        size_t path_length = strlen(tm_profile_input_root(profile, index));
        if (path_length > (SIZE_MAX - capacity - 3) / 2) {
            errno = EOVERFLOW; return -1;
        }
        capacity += 2 * path_length + 3;
    }
    for (index = 0; index < output_root_count; index++) {
        size_t path_length = strlen(output_roots[index]);
        if (path_length > (SIZE_MAX - capacity - 3) / 2) {
            errno = EOVERFLOW; return -1;
        }
        capacity += 2 * path_length + 3;
    }
    if (tm_profile_scratch_root_count(profile) > (SIZE_MAX - capacity) / 2) {
        errno = EOVERFLOW; return -1;
    }
    capacity += 2 * tm_profile_scratch_root_count(profile);
    if (output_root_count > (SIZE_MAX - capacity) / 3) {
        errno = EOVERFLOW; return -1;
    }
    capacity += 3 * output_root_count;
    if (capacity > SIZE_MAX - command_count) { errno = EOVERFLOW; return -1; }
    capacity += command_count;
    if (init_arguments(arguments, capacity) < 0) return -1;

    if (push_argument(arguments, BWRAP_PATH) < 0) return -1;
    if (strcmp(tm_profile_backend_contract(profile),
               "bubblewrap-linux-x86_64-v2") == 0) {
        if (push_argument(arguments, "--unshare-user") < 0 ||
            push_argument(arguments, "--unshare-ipc") < 0 ||
            push_argument(arguments, "--unshare-pid") < 0 ||
            push_argument(arguments, "--unshare-net") < 0 ||
            push_argument(arguments, "--unshare-uts") < 0 ||
            push_argument(arguments, "--unshare-cgroup") < 0 ||
            push_pair(arguments, "--uid", "0") < 0 ||
            push_pair(arguments, "--gid", "0") < 0)
            return -1;
    } else if (push_argument(arguments, "--unshare-all") < 0) {
        return -1;
    }
    {
        int runtime_fd = open_directory_without_symlinks(runtime_root);
        char runtime_digest[72];
        if (runtime_fd < 0) return -1;
        if (digest_profile_runtime(runtime_fd, profile, runtime_digest) < 0) {
            int saved = errno;
            close(runtime_fd);
            errno = saved;
            return -1;
        }
        if (strcmp(runtime_digest, tm_profile_runtime_digest(profile)) != 0) {
            close(runtime_fd);
            errno = ESTALE;
            return -1;
        }
        if (tm_backend_executable_identity(&bubblewrap_path,
                                           bubblewrap_digest) < 0) {
            int saved = errno;
            close(runtime_fd);
            errno = saved;
            return -1;
        }
        free(arguments->items[0]);
        arguments->items[0] = bubblewrap_path;
        (void)bubblewrap_digest;
        if (push_argument(arguments, "--die-with-parent") < 0 ||
            push_readonly_bind_fd(arguments, runtime_fd, "/") < 0) {
            close(runtime_fd);
            return -1;
        }
    }
    if (
        push_pair(arguments, "--tmpfs", GUEST_WORKSPACE) < 0 ||
        push_pair(arguments, "--tmpfs", GUEST_METADATA) < 0 ||
        push_pair(arguments, "--tmpfs", "/dev") < 0 ||
        push_argument(arguments, "--dev-bind") < 0 ||
        push_argument(arguments, "/dev/null") < 0 ||
        push_argument(arguments, "/dev/null") < 0)
        return -1;
    if (push_input_parent_directories(arguments, profile) < 0 ||
        push_output_parent_directories(arguments, output_roots,
                                       output_root_count) < 0) return -1;
    for (index = 0; index < tm_profile_input_root_count(profile); index++)
        if (push_input_mount(arguments, snapshot, index,
                             tm_profile_input_root(profile, index)) < 0)
            return -1;
    for (index = 0; index < tm_profile_scratch_root_count(profile); index++)
        if (push_pair(arguments, "--tmpfs",
                      tm_profile_scratch_root(profile, index)) < 0)
            return -1;
    for (index = 0; index < output_root_count; index++)
        if (output_fds == NULL || output_fds[index] < 0 ||
            push_output_mount(arguments, &output_fds[index],
                              output_roots[index]) < 0) return -1;
    if (push_pair(arguments, "--remount-ro", GUEST_WORKSPACE) < 0)
        return -1;

    environment_added = add_environment(arguments, profile);
    if (environment_added <= 0) return environment_added;
    length = strlen(GUEST_WORKSPACE) + strlen(relative_cwd) + 2;
    guest_cwd = malloc(length);
    if (guest_cwd == NULL) return -1;
    if (strcmp(relative_cwd, ".") == 0)
        (void)snprintf(guest_cwd, length, "%s", GUEST_WORKSPACE);
    else
        (void)snprintf(guest_cwd, length, "%s/%s", GUEST_WORKSPACE,
                       relative_cwd);
    if (push_pair(arguments, "--chdir", guest_cwd) < 0 ||
        push_argument(arguments, "--") < 0) {
        free(guest_cwd);
        return -1;
    }
    free(guest_cwd);
    for (index = 0; command[index] != NULL; index++)
        if (push_argument(arguments, command[index]) < 0) return -1;
    return 1;
}

static int run_probe(const struct argument_vector *arguments,
                     const struct tm_profile *profile, int explain)
{
    static const char probe_script[] =
        "for p in /workspace/.tm/* /workspace/.tm/.[!.]* "
        "/workspace/.tm/..?*; do "
        "[ ! -e \"$p\" ] && [ ! -L \"$p\" ] || exit 91; done; "
        "p=/.tm-runtime-write-probe-$$; "
        "[ ! -e \"$p\" ] && [ ! -L \"$p\" ] || exit 92; "
        "if (umask 077; : >\"$p\") 2>/dev/null; then "
        "rm -f -- \"$p\"; exit 93; fi; "
        "p=/workspace/.tm-workspace-write-probe-$$; "
        "if (umask 077; : >\"$p\") 2>/dev/null; then "
        "rm -f -- \"$p\"; exit 96; fi; "
        "for scratch do p=\"$scratch/.tm-scratch-probe-$$\"; "
        "(umask 077; : >\"$p\") || exit 94; "
        "rm -f -- \"$p\" || exit 95; done; "
        "p=/workspace/.tm/.tm-profile-probe-$$; "
        ": >\"$p\" && rm -f -- \"$p\"";
    struct argument_vector probe = {0};
    size_t index, separator = arguments->count;
    size_t scratch_count = tm_profile_scratch_root_count(profile);
    pid_t child;
    int status = 0;
    pid_t waited;
    for (index = 0; index < arguments->count; index++)
        if (strcmp(arguments->items[index], "--") == 0) {
            separator = index;
            break;
        }
    if (separator == arguments->count) goto unavailable;
    if (scratch_count > SIZE_MAX - separator - 6 ||
        init_arguments(&probe, separator + scratch_count + 6) < 0)
        goto unavailable;
    for (index = 0; index <= separator; index++)
        if (push_argument(&probe, arguments->items[index]) < 0) goto unavailable;
    if (push_argument(&probe, "/bin/sh") < 0 ||
        push_argument(&probe, "-c") < 0 ||
        push_argument(&probe, probe_script) < 0 ||
        push_argument(&probe, "tm-profile-view-probe") < 0)
        goto unavailable;
    for (index = 0; index < scratch_count; index++)
        if (push_argument(&probe, tm_profile_scratch_root(profile, index)) < 0)
            goto unavailable;
    child = fork();
    if (child < 0) goto unavailable;
    if (child == 0) {
        if (close_child_descriptors(arguments->preserved_fds,
                                    arguments->preserved_fd_count) < 0)
            _exit(125);
        (void)umask(022);
        if (!explain) {
            int null_fd = open("/dev/null", O_RDWR);
            if (null_fd < 0 || dup2(null_fd, STDERR_FILENO) < 0) _exit(125);
            if (null_fd != STDERR_FILENO) close(null_fd);
        }
        execv(probe.items[0], probe.items);
        _exit(127);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) goto unavailable;
    free_arguments(&probe);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
unavailable:
    free_arguments(&probe);
    return 0;
}

int tm_backend_preflight(const struct tm_profile *profile,
                         const char *runtime_root,
                         const char *repository_root,
                         const struct tm_snapshot *snapshot)
{
    struct argument_vector arguments = {0};
    const char **input_paths = NULL;
    char *runtime = NULL, *current = NULL, *working_directory = NULL;
    char *command[] = {"/bin/true", NULL};
    size_t input_count, index;
    int repository_fd = -1, built, result = 0;
    if (profile == NULL || runtime_root == NULL || repository_root == NULL)
        return 0;
    runtime = realpath(runtime_root, NULL);
    current = getcwd(NULL, 0);
    if (runtime == NULL || current == NULL) goto done;
    working_directory = tm_repo_relative_path(repository_root, current);
    if (working_directory == NULL) goto done;
    repository_fd = open_directory_without_symlinks(repository_root);
    if (repository_fd < 0) goto done;
    input_count = tm_profile_input_root_count(profile);
    if (input_count > 0) {
        input_paths = calloc(input_count, sizeof(*input_paths));
        if (input_paths == NULL) goto done;
        for (index = 0; index < input_count; index++)
            input_paths[index] = tm_profile_input_root(profile, index);
    }
    built = build_arguments(&arguments, profile, runtime, snapshot,
                            working_directory, NULL, NULL, 0, command);
    if (built > 0) result = run_probe(&arguments, profile, 0);
done:
    if (repository_fd >= 0) close(repository_fd);
    free_arguments(&arguments);
    free(input_paths);
    free(working_directory);
    free(current);
    free(runtime);
    return result;
}

static int run_bubblewrap(const struct argument_vector *arguments,
                          int explain, struct tm_observer_report *report,
                          char **command, const char *working_directory,
                          const char *const *output_roots,
                          size_t output_root_count,
                          int controlled_runtime,
                          int normalized_identity,
                          int *command_result)
{
    const char *target = command[0];
    char *relative_target = NULL;
    if (target[0] != '/' && strchr(target, '/') != NULL) {
        const char *cwd = strcmp(working_directory, ".") == 0 ? "" :
                          working_directory;
        size_t length = strlen(GUEST_WORKSPACE) + strlen(cwd) +
                        strlen(target) + 3;
        relative_target = malloc(length);
        if (relative_target != NULL) {
            (void)snprintf(relative_target, length, "%s/%s%s%s",
                GUEST_WORKSPACE, cwd, *cwd == '\0' ? "" : "/", target);
            target = relative_target;
        }
    }
    *command_result = tm_observe_and_run_with_fds_identity(
        arguments->items, explain, NULL, GUEST_WORKSPACE,
        arguments->preserved_fds, arguments->preserved_fd_count, 1, 1,
        target, controlled_runtime, normalized_identity,
        output_roots, output_root_count, report);
    free(relative_target);
    return 1;
}

static int append_declared_input_candidates(
    struct tm_observer_report *report,
    const char *const *declared_inputs, size_t declared_input_count)
{
    size_t index;
    if (report == NULL ||
        report->candidate_count > TM_OBSERVER_MAX_CANDIDATES ||
        (declared_input_count > 0 && declared_inputs == NULL) ||
        declared_input_count > TM_OBSERVER_MAX_CANDIDATES -
            report->candidate_count) {
        errno = EOVERFLOW;
        return -1;
    }
    for (index = 0; index < declared_input_count; index++) {
        struct tm_observer_candidate *candidate =
            &report->candidates[report->candidate_count];
        int path_length;
        if (declared_inputs[index] == NULL) {
            errno = EINVAL;
            return -1;
        }
        path_length = snprintf(candidate->path, sizeof(candidate->path),
                               "%s", declared_inputs[index]);
        if (path_length < 0 || (size_t)path_length >= sizeof(candidate->path)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        (void)snprintf(candidate->kind, sizeof(candidate->kind), "opened file");
        candidate->external = 0;
        report->candidate_count++;
    }
    return 0;
}

int tm_backend_run(const struct tm_profile *profile,
                   const char *runtime_root, const char *repository_root,
                   const char *const *declared_inputs,
                   size_t declared_input_count,
                   const char *const *output_roots, size_t output_root_count,
                   char **command, int explain,
                   struct tm_observer_report *report,
                   struct tm_observed_input_manifest *observed_inputs,
                   struct tm_output_manifest *output_manifest,
                   int *command_result)
{
    struct argument_vector arguments = {0};
    struct tm_snapshot *snapshot = NULL;
    const char **input_paths = NULL;
    int *output_fds = NULL;
    char *runtime = NULL, *current = NULL, *working_directory = NULL;
    char *output_stage_path = NULL;
    int output_stage_fd = -1;
    size_t input_count, index;
    int repository_fd = -1, built, result = 0;
    int controlled_runtime = 1;
    int normalized_identity = 0;

    if (profile == NULL || runtime_root == NULL || repository_root == NULL ||
        command == NULL || command[0] == NULL || command_result == NULL ||
        report == NULL || observed_inputs == NULL || output_manifest == NULL)
        return 0;
#ifndef TM_TEST_BWRAP
    normalized_identity = strcmp(tm_profile_backend_contract(profile),
                                  "bubblewrap-linux-x86_64-v2") == 0;
#else
    controlled_runtime = 0;
#endif
    memset(observed_inputs, 0, sizeof(*observed_inputs));
    tm_output_manifest_clear(output_manifest);
    if (output_root_count > 0 &&
        create_output_stage(output_roots, output_root_count,
            &output_stage_path, &output_stage_fd, &output_fds) < 0) {
        if (explain)
            fprintf(stderr,
                "tm: RUN: declared output staging failed (%s); using uncached host execution\n",
                strerror(errno));
        return 0;
    }
    runtime = realpath(runtime_root, NULL);
    current = getcwd(NULL, 0);
    if (runtime == NULL || current == NULL) goto done;
    working_directory = tm_repo_relative_path(repository_root, current);
    if (working_directory == NULL) goto done;
    repository_fd = open_directory_without_symlinks(repository_root);
    if (repository_fd < 0) goto done;
    input_count = tm_profile_input_root_count(profile);
    if (input_count > 0) {
        input_paths = calloc(input_count, sizeof(*input_paths));
        if (input_paths == NULL) goto done;
        for (index = 0; index < input_count; index++)
            input_paths[index] = tm_profile_input_root(profile, index);
        if (tm_snapshot_create(repository_fd, input_paths, input_count,
                               &snapshot) < 0) {
            if (explain)
                fprintf(stderr,
                    "tm: RUN: approved inputs could not be snapshotted (%s); using uncached native execution\n",
                    strerror(errno));
            goto done;
        }
    }
    built = build_arguments(&arguments, profile, runtime, snapshot,
                            working_directory, output_roots,
                            output_fds, output_root_count, command);
    close(repository_fd);
    repository_fd = -1;
    if (built <= 0) {
        if (explain && built == 0)
            fprintf(stderr,
                "tm: RUN: approved profile environment cannot be enforced; using uncached native execution\n");
        else if (explain && errno == EROFS)
            fprintf(stderr,
                "tm: RUN: approved runtime is not a root-owned read-only tree; using uncached native execution\n");
        else if (explain && errno == EPERM)
            fprintf(stderr,
                "tm: RUN: Bubblewrap executable is not a trusted root-owned read-only file; using uncached native execution\n");
        else if (explain)
            fprintf(stderr,
                "tm: RUN: approved input view could not be constructed (%s); using uncached native execution\n",
                strerror(errno));
        goto done;
    }
    if (!run_probe(&arguments, profile, explain)) {
        if (explain)
            fprintf(stderr,
                "tm: RUN: Bubblewrap profile view is unavailable; running once without reuse\n");
        goto done;
    }
    if (explain)
        fprintf(stderr,
            "tm: RUN: Bubblewrap restricted input roots and read-only workspace/runtime views active; lookup remains disabled\n");
    result = run_bubblewrap(&arguments, explain, report, command,
                            working_directory, output_roots,
                            output_root_count, controlled_runtime,
                            normalized_identity,
                            command_result);
    if (result > 0 && *command_result == 0 && output_root_count > 0) {
        repository_fd = open_directory_without_symlinks(repository_root);
        if (repository_fd < 0) {
            int saved = errno;
            tm_output_manifest_clear(output_manifest);
            fprintf(stderr,
                "tm: output warning: child succeeded, but repository could not be reopened (%s)\n",
                strerror(saved));
        } else if (tm_outputs_capture_to_store(output_stage_fd, repository_fd,
                output_roots, output_root_count, output_manifest) < 0) {
            int saved = errno;
            tm_output_manifest_clear(output_manifest);
            fprintf(stderr,
                "tm: output warning: child succeeded, but declared outputs could not be safely captured (%s)\n",
                strerror(saved));
        } else if (tm_outputs_restore_from_store(repository_fd, repository_fd,
                output_roots, output_root_count, output_manifest) < 0) {
            int saved = errno;
            tm_output_manifest_clear(output_manifest);
            fprintf(stderr,
                "tm: output warning: child succeeded, but declared outputs could not be safely restored (%s)\n",
                strerror(saved));
        }
        if (repository_fd >= 0) {
            close(repository_fd);
            repository_fd = -1;
        }
    }
    if (result > 0 && tm_observer_report_allows_reuse(report)) {
        if (append_declared_input_candidates(report, declared_inputs,
                declared_input_count) < 0) {
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_UNSUPPORTED;
            report->stable_input_view = 0;
            if (explain)
                fprintf(stderr,
                    "tm: reuse rejected: declared inputs could not be added to the pinned manifest (%s)\n",
                    strerror(errno));
            goto done;
        }
        int *readable_roots = input_count == 0 ? NULL :
            calloc(input_count, sizeof(*readable_roots));
        int capture_result = input_count == 0 ?
            (report->candidate_count == 0 ? 0 : -1) :
            (readable_roots == NULL ? -1 : 0);
        if (input_count == 0 && report->candidate_count != 0)
            errno = EXDEV;
        if (capture_result == 0) {
            for (index = 0; index < input_count; index++) {
                readable_roots[index] = tm_snapshot_open_root_readable(
                    snapshot, index);
                if (readable_roots[index] < 0) {
                    capture_result = -1;
                    break;
                }
            }
        }
        if (capture_result == 0 && input_count > 0)
            capture_result = tm_observer_capture_snapshot_inputs(report,
                input_paths, readable_roots, input_count, observed_inputs);
        if (readable_roots != NULL) {
            for (index = 0; index < input_count; index++)
                if (readable_roots[index] >= 0) close(readable_roots[index]);
            free(readable_roots);
        }
        if (capture_result < 0) {
            tm_observed_input_manifest_clear(observed_inputs);
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_UNSUPPORTED;
            report->stable_input_view = 0;
            if (explain)
                fprintf(stderr,
                    "tm: reuse rejected: observed inputs could not be captured from pinned snapshots (%s)\n",
                    strerror(errno));
        } else if (explain) {
            fprintf(stderr,
                "tm: captured %zu observed inputs from pinned snapshots (lookup remains disabled)\n",
                observed_inputs->count);
        }
    }
done:
    if (repository_fd >= 0) close(repository_fd);
    free_arguments(&arguments);
    if (output_stage_fd >= 0) {
        (void)remove_output_stage_contents(output_stage_fd, 0);
        close(output_stage_fd);
    }
    if (output_stage_path != NULL) {
        (void)rmdir(output_stage_path);
        free(output_stage_path);
    }
    if (output_fds != NULL) {
        for (index = 0; index < output_root_count; index++)
            if (output_fds[index] >= 0) close(output_fds[index]);
        free(output_fds);
    }
    if (result <= 0 || *command_result != 0)
        tm_output_manifest_clear(output_manifest);
    tm_snapshot_free(snapshot);
    free(input_paths);
    free(working_directory);
    free(current);
    free(runtime);
    return result;
}
