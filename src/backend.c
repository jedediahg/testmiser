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
    current = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
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
            O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
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

static int push_output_mount(struct argument_vector *arguments,
                             const char *path)
{
    char *guest_path;
    size_t length = strlen(path) + sizeof(GUEST_WORKSPACE) + 1;
    int result;
    guest_path = malloc(length);
    if (guest_path == NULL) return -1;
    if (snprintf(guest_path, length, "%s/%s", GUEST_WORKSPACE, path) < 0) {
        free(guest_path);
        errno = EIO;
        return -1;
    }
    result = push_pair(arguments, "--tmpfs", guest_path);
    free(guest_path);
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
                           size_t output_root_count,
                           char **command)
{
    char *guest_cwd = NULL;
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
    if (tm_profile_scratch_root_count(profile) > (SIZE_MAX - capacity) / 2) {
        errno = EOVERFLOW; return -1;
    }
    capacity += 2 * tm_profile_scratch_root_count(profile);
    if (output_root_count > (SIZE_MAX - capacity) / 2) {
        errno = EOVERFLOW; return -1;
    }
    capacity += 2 * output_root_count;
    if (capacity > SIZE_MAX - command_count) { errno = EOVERFLOW; return -1; }
    capacity += command_count;
    if (init_arguments(arguments, capacity) < 0) return -1;

    if (push_argument(arguments, BWRAP_PATH) < 0)
        return -1;
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
        if (tm_runtime_tree_digest_fd(runtime_fd, runtime_digest) < 0) {
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
        if (push_argument(arguments, "--die-with-parent") < 0 ||
            push_readonly_bind_fd(arguments, runtime_fd, "/") < 0) {
            close(runtime_fd);
            return -1;
        }
    }
    if (
        push_pair(arguments, "--tmpfs", GUEST_WORKSPACE) < 0 ||
        push_pair(arguments, "--tmpfs", GUEST_METADATA) < 0 ||
        push_argument(arguments, "--dev-bind") < 0 ||
        push_argument(arguments, "/dev/null") < 0 ||
        push_argument(arguments, "/dev/null") < 0)
        return -1;
    if (push_input_parent_directories(arguments, profile) < 0) return -1;
    for (index = 0; index < tm_profile_input_root_count(profile); index++)
        if (push_input_mount(arguments, snapshot, index,
                             tm_profile_input_root(profile, index)) < 0)
            return -1;
    for (index = 0; index < tm_profile_scratch_root_count(profile); index++)
        if (push_pair(arguments, "--tmpfs",
                      tm_profile_scratch_root(profile, index)) < 0)
            return -1;
    for (index = 0; index < output_root_count; index++)
        if (push_output_mount(arguments, output_roots[index]) < 0) return -1;
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
                     const struct tm_profile *profile)
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
        "p=/workspace/.tm-profile-probe-$$; "
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
        int null_fd;
        if (close_child_descriptors(arguments->preserved_fds,
                                    arguments->preserved_fd_count) < 0)
            _exit(125);
        (void)umask(022);
        null_fd = open("/dev/null", O_RDWR);
        if (null_fd < 0 || dup2(null_fd, STDERR_FILENO) < 0) _exit(125);
        if (null_fd != STDERR_FILENO) close(null_fd);
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

static int run_bubblewrap(const struct argument_vector *arguments,
                          int *command_result)
{
    pid_t child = fork(), waited;
    int status = 0;
    if (child < 0) return 0;
    if (child == 0) {
        int null_fd;
        if (close_child_descriptors(arguments->preserved_fds,
                                    arguments->preserved_fd_count) < 0)
            _exit(125);
        (void)umask(022);
        null_fd = open("/dev/null", O_RDONLY);
        if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0) _exit(125);
        if (null_fd != STDIN_FILENO) close(null_fd);
        execv(arguments->items[0], arguments->items);
        _exit(127);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child) {
        fprintf(stderr, "tm: wait for Bubblewrap failed: %s\n", strerror(errno));
        *command_result = 125;
        return 1;
    }
    if (WIFEXITED(status)) *command_result = WEXITSTATUS(status);
    else if (WIFSIGNALED(status))
        *command_result = 128 + WTERMSIG(status);
    else *command_result = 125;
    return 1;
}

int tm_backend_run(const struct tm_profile *profile,
                   const char *runtime_root, const char *repository_root,
                   const char *const *output_roots, size_t output_root_count,
                   char **command, int explain,
                   struct tm_observer_report *report, int *command_result)
{
    struct argument_vector arguments = {0};
    struct tm_snapshot *snapshot = NULL;
    const char **input_paths = NULL;
    char *runtime = NULL, *current = NULL, *working_directory = NULL;
    size_t input_count, index;
    int repository_fd = -1, built, result = 0;

    if (profile == NULL || runtime_root == NULL || repository_root == NULL ||
        command == NULL || command[0] == NULL || command_result == NULL)
        return 0;
    if (output_root_count != 0) {
        if (explain)
            fprintf(stderr,
                "tm: RUN: declared output restoration is not integrated; using uncached host execution\n");
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
                            output_root_count, command);
    close(repository_fd);
    repository_fd = -1;
    if (built <= 0) {
        if (explain && built == 0)
            fprintf(stderr,
                "tm: RUN: approved profile environment cannot be enforced; using uncached native execution\n");
        else if (explain)
            fprintf(stderr,
                "tm: RUN: approved input view could not be constructed (%s); using uncached native execution\n",
                strerror(errno));
        goto done;
    }
    if (!run_probe(&arguments, profile)) {
        if (explain)
            fprintf(stderr,
                "tm: RUN: Bubblewrap profile view is unavailable; running once without reuse\n");
        goto done;
    }
    if (explain)
        fprintf(stderr,
            "tm: RUN: Bubblewrap restricted input roots and read-only workspace/runtime views active; cache reuse remains disabled\n");
    (void)report;
    result = run_bubblewrap(&arguments, command_result);
done:
    if (repository_fd >= 0) close(repository_fd);
    free_arguments(&arguments);
    tm_snapshot_free(snapshot);
    free(input_paths);
    free(working_directory);
    free(current);
    free(runtime);
    return result;
}
