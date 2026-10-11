#define _GNU_SOURCE

#include <errno.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__) && defined(__x86_64__)
#include <linux/close_range.h>
#include <linux/openat2.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#endif

#include "tm/observer.h"
#include "tm/repo.h"
#include "tm/tm.h"

extern char **environ;

#define TM_FORWARDED_SIGNAL_COUNT 4
static const int forwarded_signals[TM_FORWARDED_SIGNAL_COUNT] = {
    SIGINT, SIGTERM, SIGHUP, SIGQUIT
};
static volatile sig_atomic_t received_wrapper_signal;
static volatile sig_atomic_t forwarded_wrapper_signal;

static void forward_wrapper_signal(int signal_number)
{
    if (received_wrapper_signal == 0) {
        received_wrapper_signal = signal_number;
    }
}

static int install_signal_forwarding(struct sigaction previous[])
{
    struct sigaction action;
    size_t index;
    memset(&action, 0, sizeof(action));
    action.sa_handler = forward_wrapper_signal;
    sigemptyset(&action.sa_mask);
    received_wrapper_signal = 0;
    forwarded_wrapper_signal = 0;
    for (index = 0; index < TM_FORWARDED_SIGNAL_COUNT; index++) {
        if (sigaction(forwarded_signals[index], &action, &previous[index]) < 0) {
            while (index > 0) {
                index--;
                (void)sigaction(forwarded_signals[index], &previous[index], NULL);
            }
            return -1;
        }
    }
    return 0;
}

static void restore_signal_handlers(const struct sigaction previous[])
{
    size_t index;
    for (index = 0; index < TM_FORWARDED_SIGNAL_COUNT; index++)
        (void)sigaction(forwarded_signals[index], &previous[index], NULL);
}

#if defined(__linux__) && defined(__x86_64__)

#define TM_MAX_TASKS 4096
#define TM_PATH_SIZE 1024
#define TM_MAX_CANDIDATES TM_OBSERVER_MAX_CANDIDATES
#define TM_MAX_UNSUPPORTED 32
#define TM_MAX_DESCRIPTORS 128

struct fd_entry {
    int descriptor;
    unsigned long flags;
    int is_directory;
    char *path;
};

struct task_state {
    pid_t pid;
    int active;
    int in_execution_tree;
    int syscall_entry;
    long syscall_number;
    unsigned long flags;
    int shares_descriptors;
    int pending_descriptor;
    int pending_duplication;
    int pending_close_on_exec;
    int pending_close_range;
    int pending_cwd_change;
    int pending_cwd_is_directory;
    unsigned int pending_range_start;
    unsigned int pending_range_end;
    char pending_path[TM_PATH_SIZE];
    size_t fd_count;
    struct fd_entry descriptors[TM_MAX_DESCRIPTORS];
};

struct observer_state {
    int explain;
    const char *repository_root;
    int controlled_runtime;
    int normalized_identity;
    const char *const *output_roots;
    size_t output_root_count;
    const char *start_after_exec;
    int observation_started;
    pid_t direct_pid;
    int direct_status;
    int direct_finished;
    unsigned int live_tasks;
    int saw_unknown_syscall;
    int saw_network;
    int saw_mutation;
    int saw_metadata;
    int saw_directory;
    int saw_external_descriptor;
    int saw_observer_failure;
    int saw_outliving_descendant;
    int saw_external_path;
    int saw_unmodeled_error;
    int saw_context;
    size_t candidate_count;
    size_t unsupported_count;
    long unsupported_syscalls[TM_MAX_UNSUPPORTED];
    char candidates[TM_MAX_CANDIDATES][TM_PATH_SIZE + 32];
};

static struct task_state tasks[TM_MAX_TASKS];
static struct observer_state observer;
static const char *tracked_descriptor(const struct task_state *task, int fd);

static int path_is_declared_output(const char *path)
{
    size_t index;
    if (path == NULL || observer.output_roots == NULL ||
        observer.repository_root == NULL) return 0;
    for (index = 0; index < observer.output_root_count; index++) {
        char root[TM_PATH_SIZE];
        int length = snprintf(root, sizeof(root), "%s/%s",
            observer.repository_root, observer.output_roots[index]);
        if (length < 0 || (size_t)length >= sizeof(root)) continue;
        if (strncmp(path, root, (size_t)length) == 0) {
            const char *component = path + length;
            if (*component == '\0') return 1;
            if (*component++ != '/') continue;
            while (*component != '\0') {
                const char *end = strchr(component, '/');
                size_t component_length = end == NULL ? strlen(component) :
                    (size_t)(end - component);
                if (component_length == 0 ||
                    (component_length == 1 && component[0] == '.') ||
                    (component_length == 2 && component[0] == '.' &&
                     component[1] == '.')) break;
                if (end == NULL) return 1;
                component = end + 1;
            }
        }
    }
    return 0;
}

static int descriptor_is_declared_output(const struct task_state *task,
                                         int descriptor)
{
    return path_is_declared_output(tracked_descriptor(task, descriptor));
}

static int process_parent(pid_t process, pid_t *parent)
{
    char path[64], line[4096], state;
    char *closing_command;
    long parent_value;
    FILE *stream;
    if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)process) >=
        (int)sizeof(path)) return -1;
    stream = fopen(path, "r");
    if (stream == NULL) return -1;
    if (fgets(line, sizeof(line), stream) == NULL) {
        fclose(stream);
        return -1;
    }
    fclose(stream);
    closing_command = strrchr(line, ')');
    if (closing_command == NULL ||
        sscanf(closing_command + 2, "%c %ld", &state, &parent_value) != 2 ||
        parent_value < 1) return -1;
    *parent = (pid_t)parent_value;
    return 0;
}

static void signal_process_tree(pid_t root, int signal_number)
{
    pid_t processes[16384];
    size_t count = 1;
    DIR *proc = opendir("/proc");
    int added;
    processes[0] = root;
    if (proc == NULL) {
        (void)kill(root, signal_number);
        return;
    }
    do {
        struct dirent *entry;
        added = 0;
        rewinddir(proc);
        while ((entry = readdir(proc)) != NULL && count <
               sizeof(processes) / sizeof(processes[0])) {
            char *end;
            long value;
            pid_t parent;
            size_t index;
            value = strtol(entry->d_name, &end, 10);
            if (entry->d_name[0] == '\0' || *end != '\0' || value < 1 ||
                value > INT32_MAX) continue;
            for (index = 0; index < count; index++)
                if (processes[index] == (pid_t)value) break;
            if (index != count || process_parent((pid_t)value, &parent) < 0)
                continue;
            for (index = 0; index < count; index++)
                if (processes[index] == parent) break;
            if (index != count) {
                processes[count++] = (pid_t)value;
                added = 1;
            }
        }
    } while (added && count < sizeof(processes) / sizeof(processes[0]));
    closedir(proc);
    for (size_t index = count; index > 1; index--)
        (void)kill(processes[index - 1], signal_number);
    (void)kill(root, signal_number);
    forwarded_wrapper_signal = signal_number;
}

static void forward_pending_signal(pid_t child)
{
    int signal_number = (int)received_wrapper_signal;
    if (signal_number != 0 && forwarded_wrapper_signal == 0)
        signal_process_tree(child, signal_number);
}

static int has_inherited_descriptors(void)
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int scan_descriptor;
    int ineligible = 0;
    if (directory == NULL) return 1;
    scan_descriptor = dirfd(directory);
    for (;;) {
        char *end;
        long descriptor;
        int flags;
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) ineligible = 1;
            break;
        }
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        descriptor = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || descriptor <= STDERR_FILENO ||
            descriptor == scan_descriptor) continue;
        flags = fcntl((int)descriptor, F_GETFD);
        if (flags < 0) {
            if (errno == EBADF) continue;
            ineligible = 1;
            break;
        }
        if ((flags & FD_CLOEXEC) == 0) {
            ineligible = 1;
            break;
        }
    }
    closedir(directory);
    return ineligible;
}

static void mark_observer_failure(void)
{
    observer.saw_unknown_syscall = 1;
    observer.saw_observer_failure = 1;
}

static void mark_unmodeled_error(void)
{
    observer.saw_unmodeled_error = 1;
}

static void reject_unsupported_syscall(long number)
{
    size_t index;

    observer.saw_unknown_syscall = 1;
    for (index = 0; index < observer.unsupported_count; index++) {
        if (observer.unsupported_syscalls[index] == number) {
            return;
        }
    }
    if (observer.unsupported_count < TM_MAX_UNSUPPORTED) {
        observer.unsupported_syscalls[observer.unsupported_count++] = number;
    } else {
        observer.saw_observer_failure = 1;
    }
}

static struct task_state *find_task(pid_t pid)
{
    size_t index;

    for (index = 0; index < TM_MAX_TASKS; index++) {
        if (tasks[index].active && tasks[index].pid == pid) {
            return &tasks[index];
        }
    }
    return NULL;
}

static const char *tracked_descriptor(const struct task_state *task, int fd)
{
    size_t index;
    for (index = 0; index < task->fd_count; index++)
        if (task->descriptors[index].descriptor == fd)
            return task->descriptors[index].path;
    return NULL;
}

static int descriptor_is_directory(const struct task_state *task, int fd)
{
    size_t index;
    for (index = 0; index < task->fd_count; index++)
        if (task->descriptors[index].descriptor == fd)
            return task->descriptors[index].is_directory;
    return 0;
}

static void forget_descriptor(struct task_state *task, int fd)
{
    size_t index;
    for (index = 0; index < task->fd_count; index++) {
        if (task->descriptors[index].descriptor == fd) {
            free(task->descriptors[index].path);
            task->descriptors[index] = task->descriptors[task->fd_count - 1];
            task->fd_count--;
            return;
        }
    }
}

/* GCC 12's analyzer treats paths retained by the global task table as lost;
 * forget_descriptor(), finish_task(), and detach_descendants() own cleanup. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wanalyzer-malloc-leak"
#endif
static int remember_descriptor(struct task_state *task, int fd,
                               unsigned long flags, int is_directory,
                               const char *path)
{
    struct fd_entry *entry;
    if (fd < 0 || fd > 1048576 || path == NULL) return -1;
    forget_descriptor(task, fd);
    if (task->fd_count == TM_MAX_DESCRIPTORS) return -1;
    entry = &task->descriptors[task->fd_count];
    entry->path = strdup(path);
    if (entry->path == NULL) return -1;
    entry->descriptor = fd;
    entry->flags = flags;
    entry->is_directory = is_directory;
    task->fd_count++;
    return 0;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static int copy_descriptors(struct task_state *destination,
                            const struct task_state *source)
{
    size_t index;
    for (index = 0; index < source->fd_count; index++)
        if (remember_descriptor(destination,
                source->descriptors[index].descriptor,
                source->descriptors[index].flags,
                source->descriptors[index].is_directory,
                source->descriptors[index].path) < 0) return -1;
    return 0;
}

static void forget_cloexec_descriptors(struct task_state *task)
{
    size_t index = 0;
    while (index < task->fd_count) {
        if ((task->descriptors[index].flags & O_CLOEXEC) != 0) {
            forget_descriptor(task, task->descriptors[index].descriptor);
        } else {
            index++;
        }
    }
}

static struct task_state *add_task(pid_t pid)
{
    size_t index;

    if (find_task(pid) != NULL) {
        return find_task(pid);
    }
    for (index = 0; index < TM_MAX_TASKS; index++) {
        if (!tasks[index].active) {
            memset(&tasks[index], 0, sizeof(tasks[index]));
            tasks[index].pid = pid;
            tasks[index].active = 1;
            observer.live_tasks++;
            return &tasks[index];
        }
    }
    return NULL;
}

static void finish_task(pid_t pid, int status)
{
    struct task_state *task = find_task(pid);
    size_t index;

    if (task == NULL) {
        return;
    }
    task->active = 0;
    observer.live_tasks--;
    for (index = 0; index < task->fd_count; index++)
        free(task->descriptors[index].path);
    task->fd_count = 0;
    if (pid == observer.direct_pid) {
        observer.direct_status = status;
        observer.direct_finished = 1;
    }
}

static int read_tracee_string(pid_t pid, unsigned long address, char *output,
                              size_t capacity)
{
    size_t copied = 0;

    if (address == 0 || capacity < sizeof(long)) {
        return -1;
    }
    while (copied < capacity - 1) {
        long word;
        size_t byte_index;

        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid,
                      (void *)(address + copied), NULL);
        if (word == -1 && errno != 0) {
            return -1;
        }
        for (byte_index = 0; byte_index < sizeof(word); byte_index++) {
            char value = (char)((unsigned long)word >> (byte_index * 8));
            output[copied++] = value;
            if (value == '\0') {
                return 0;
            }
            if (copied >= capacity - 1) {
                break;
            }
        }
    }
    output[capacity - 1] = '\0';
    return -1;
}

static int read_tracee_memory(pid_t pid, unsigned long address, void *output,
                              size_t length)
{
    size_t copied = 0;
    unsigned char *bytes = output;
    while (copied < length) {
        long word;
        size_t amount = sizeof(word);
        if (amount > length - copied) amount = length - copied;
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid,
                      (void *)(address + copied), NULL);
        if (word == -1 && errno != 0) return -1;
        memcpy(bytes + copied, &word, amount);
        copied += amount;
    }
    return 0;
}

static void task_path(pid_t pid, int dirfd, const char *path, char *output,
                      size_t capacity)
{
    char proc_path[64];
    char base[TM_PATH_SIZE];
    ssize_t length;
    size_t base_length;
    size_t path_length;

    if (path[0] == '/') {
        if (snprintf(output, capacity, "%s", path) >= (int)capacity) {
            mark_observer_failure();
            snprintf(output, capacity, "<path-too-long>");
        }
        return;
    }
    if (dirfd == AT_FDCWD) {
        snprintf(proc_path, sizeof(proc_path), "/proc/%ld/cwd", (long)pid);
    } else {
        snprintf(proc_path, sizeof(proc_path), "/proc/%ld/fd/%d", (long)pid,
                 dirfd);
    }
    length = readlink(proc_path, base, sizeof(base) - 1);
    if (length < 0) {
        mark_observer_failure();
        snprintf(output, capacity, "<unresolved:%s>", path);
        return;
    }
    base[length] = '\0';
    base_length = strlen(base);
    path_length = strlen(path);
    if (base_length + path_length + 2 > capacity) {
        mark_observer_failure();
        snprintf(output, capacity, "<path-too-long>");
        return;
    }
    memcpy(output, base, base_length);
    output[base_length] = '/';
    memcpy(output + base_length + 1, path, path_length + 1);
}

static void candidate_path(const char *kind, const char *path)
{
    char candidate[TM_PATH_SIZE + 32];
    char *relative_path;
    const char *display_path;
    size_t index;
    int formatted;

    if (path_is_declared_output(path)) return;
    relative_path = tm_repo_relative_path(observer.repository_root, path);
    if (relative_path == NULL && observer.controlled_runtime) {
        if (strcmp(path, "/dev/null") == 0) {
            free(relative_path);
            return;
        }
        if (strncmp(path, "/dev/", sizeof("/dev/") - 1) != 0 &&
            strcmp(path, "/dev") != 0) {
            /* The profile backend exposes only its digest-verified runtime
             * and empty tmpfs scratch roots outside the repository. */
            free(relative_path);
            return;
        }
    }
    if (relative_path == NULL) observer.saw_external_path = 1;
    display_path = relative_path == NULL ? "<external>" : relative_path;
    formatted = snprintf(candidate, sizeof(candidate), "%s: %s", kind,
                         display_path);
    free(relative_path);
    if (formatted < 0 || (size_t)formatted >= sizeof(candidate)) {
        mark_observer_failure();
        return;
    }
    for (index = 0; index < observer.candidate_count; index++) {
        if (strcmp(observer.candidates[index], candidate) == 0) {
            return;
        }
    }
    if (observer.candidate_count < TM_MAX_CANDIDATES) {
        snprintf(observer.candidates[observer.candidate_count],
                 sizeof(observer.candidates[0]), "%s", candidate);
        observer.candidate_count++;
    } else {
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
    }
}

static void copy_candidate_report(struct tm_observer_report *report)
{
    size_t index;
    if (report == NULL) return;
    report->candidate_count = observer.candidate_count;
    for (index = 0; index < observer.candidate_count; index++) {
        const char *record = observer.candidates[index];
        const char *separator = strstr(record, ": ");
        struct tm_observer_candidate *candidate = &report->candidates[index];
        size_t kind_length;
        if (separator == NULL) {
            report->candidate_count = index;
            observer.saw_observer_failure = 1;
            break;
        }
        kind_length = (size_t)(separator - record);
        if (kind_length >= sizeof(candidate->kind)) {
            report->candidate_count = index;
            observer.saw_observer_failure = 1;
            break;
        }
        memcpy(candidate->kind, record, kind_length);
        candidate->kind[kind_length] = '\0';
        if (strcmp(separator + 2, "<external>") == 0) {
            candidate->external = 1;
            candidate->path[0] = '\0';
        } else {
            candidate->external = 0;
            if (snprintf(candidate->path, sizeof(candidate->path), "%s",
                         separator + 2) >= (int)sizeof(candidate->path)) {
                report->candidate_count = index;
                observer.saw_observer_failure = 1;
                break;
            }
        }
    }
}

static void note_syscall(long number, const struct user_regs_struct *registers,
                         struct task_state *task)
{
    char raw_path[TM_PATH_SIZE];
    int dirfd = AT_FDCWD;

    task->syscall_number = number;
    task->pending_path[0] = '\0';
    task->flags = 0;
    task->shares_descriptors = 0;
    task->pending_descriptor = -1;
    task->pending_duplication = 0;
    task->pending_close_on_exec = 0;
    task->pending_close_range = 0;
    task->pending_cwd_change = 0;
    task->pending_cwd_is_directory = 0;

    switch (number) {
    case 2: /* open */
        if (read_tracee_string(task->pid, registers->rdi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, AT_FDCWD, raw_path, task->pending_path,
                      sizeof(task->pending_path));
            task->flags = registers->rsi;
        } else {
            mark_observer_failure();
        }
        return;
    case 257: /* openat */
        dirfd = (int)registers->rdi;
        if (read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, dirfd, raw_path, task->pending_path,
                      sizeof(task->pending_path));
            task->flags = registers->rdx;
        } else {
            mark_observer_failure();
        }
        return;
    case 4:   /* stat */
    case 6:   /* lstat */
    case 21:  /* access */
        if (read_tracee_string(task->pid, registers->rdi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, AT_FDCWD, raw_path, task->pending_path,
                      sizeof(task->pending_path));
            candidate_path("metadata probe", task->pending_path);
        } else {
            mark_observer_failure();
        }
        return;
    case 76:  /* truncate */
    case 83:  /* mkdir */
    case 84:  /* rmdir */
    case 87:  /* unlink */
    case 90:  /* chmod */
        if (read_tracee_string(task->pid, registers->rdi, raw_path,
                               sizeof(raw_path)) == 0)
            task_path(task->pid, AT_FDCWD, raw_path, task->pending_path,
                      sizeof(task->pending_path));
        else
            mark_observer_failure();
        return;
    case 258: /* mkdirat */
    case 263: /* unlinkat */
    case 268: /* fchmodat */
    case 452: /* fchmodat2 */
        if (read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) == 0)
            task_path(task->pid, (int)registers->rdi, raw_path,
                      task->pending_path, sizeof(task->pending_path));
        else
            mark_observer_failure();
        return;
    case 262: /* newfstatat */
    case 269: /* faccessat */
    case 332: /* statx */
    case 439: /* faccessat2 */
        if (read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, (int)registers->rdi, raw_path,
                      task->pending_path, sizeof(task->pending_path));
            candidate_path("metadata probe", task->pending_path);
        } else {
            mark_observer_failure();
        }
        return;
    case 89:  /* readlink */
        if (read_tracee_string(task->pid, registers->rdi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, AT_FDCWD, raw_path, task->pending_path,
                      sizeof(task->pending_path));
        } else {
            mark_observer_failure();
        }
        return;
    case 267: /* readlinkat */
        if (read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, (int)registers->rdi, raw_path,
                      task->pending_path, sizeof(task->pending_path));
        } else {
            mark_observer_failure();
        }
        return;
    case 322: /* execveat: support pathname lookup only */
        if (registers->r8 != 0 ||
            read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) < 0 || raw_path[0] == '\0') {
            reject_unsupported_syscall(number);
            return;
        }
        task_path(task->pid, (int)registers->rdi, raw_path,
                  task->pending_path, sizeof(task->pending_path));
        return;
    case 437: { /* openat2 */
        struct open_how how;
        const uint64_t allowed_flags = O_RDONLY | O_CLOEXEC | O_LARGEFILE |
                                       O_DIRECTORY;
        if (registers->r10 != sizeof(how) ||
            read_tracee_memory(task->pid, registers->rdx, &how,
                               sizeof(how)) < 0 || how.resolve != 0 ||
            how.mode != 0 || (how.flags & O_ACCMODE) != O_RDONLY ||
            (how.flags & ~allowed_flags) != 0) {
            reject_unsupported_syscall(number);
            return;
        }
        if (read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, (int)registers->rdi, raw_path,
                      task->pending_path, sizeof(task->pending_path));
            task->flags = (unsigned long)how.flags;
        } else {
            mark_observer_failure();
        }
        return;
    }
    case 59: /* execve */
        if (read_tracee_string(task->pid, registers->rdi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, AT_FDCWD, raw_path, task->pending_path,
                      sizeof(task->pending_path));
        } else {
            mark_observer_failure();
        }
        return;
    case 80: /* chdir */
        task->pending_cwd_change = 1;
        task->pending_cwd_is_directory = 1;
        if (read_tracee_string(task->pid, registers->rdi, raw_path,
                               sizeof(raw_path)) == 0)
            task_path(task->pid, AT_FDCWD, raw_path, task->pending_path,
                      sizeof(task->pending_path));
        else
            mark_observer_failure();
        return;
    case 81: /* fchdir */
        task->pending_cwd_change = 1;
        task->pending_descriptor = (int)registers->rdi;
        task->pending_cwd_is_directory = descriptor_is_directory(
            task, task->pending_descriptor);
        {
            const char *path = tracked_descriptor(task,
                                                   task->pending_descriptor);
            if (path == NULL) {
                observer.saw_external_descriptor = 1;
            } else if (snprintf(task->pending_path,
                                sizeof(task->pending_path), "%s", path) >=
                       (int)sizeof(task->pending_path)) {
                mark_observer_failure();
            }
        }
        return;
    case 435: { /* clone3: inspect the descriptor-sharing flag */
        uint64_t flags;
        if (registers->rsi < sizeof(flags) ||
            read_tracee_memory(task->pid, registers->rdi, &flags,
                               sizeof(flags)) < 0) {
            reject_unsupported_syscall(number);
            return;
        }
        task->shares_descriptors = (flags & CLONE_FILES) != 0;
        return;
    }
    case 3: /* close */
        task->pending_descriptor = (int)registers->rdi;
        if (tracked_descriptor(task, task->pending_descriptor) == NULL)
            observer.saw_external_descriptor = 1;
        return;
    case 32: /* dup */
        task->pending_descriptor = (int)registers->rdi;
        task->pending_duplication = 1;
        break;
    case 33: /* dup2 */
        task->pending_descriptor = (int)registers->rdi;
        task->pending_duplication = 1;
        break;
    case 292: /* dup3 */
        task->pending_descriptor = (int)registers->rdi;
        task->pending_duplication = 1;
        task->pending_close_on_exec =
            (((unsigned long)registers->rdx & O_CLOEXEC) != 0);
        break;
    case 72: /* fcntl: only descriptor duplication is modeled */
        if (registers->rsi == F_DUPFD ||
            registers->rsi == F_DUPFD_CLOEXEC) {
            task->pending_descriptor = (int)registers->rdi;
            task->pending_duplication = 1;
            task->pending_close_on_exec =
                registers->rsi == F_DUPFD_CLOEXEC;
        }
        return;
    case 436: /* close_range: unshare mode is not modeled */
        if ((registers->rdx & ~((unsigned long)CLOSE_RANGE_CLOEXEC)) != 0) {
            reject_unsupported_syscall(number);
            return;
        }
        task->pending_range_start = (unsigned int)registers->rdi;
        task->pending_range_end = (unsigned int)registers->rsi;
        task->pending_close_on_exec =
            ((registers->rdx & CLOSE_RANGE_CLOEXEC) != 0);
        task->pending_close_range = 1;
        return;
    default:
        return;
    }
}

/* A writable private mapping uses copy-on-write and cannot mutate its source.
 * Read the stopped tracee's VMA map rather than guessing from mmap history;
 * unknown, shared, gapped, or concurrently mutable address spaces fail closed. */
static int tracee_range_is_private(pid_t pid, unsigned long address,
                                   unsigned long length)
{
    char maps_path[64];
    char *line = NULL;
    size_t line_capacity = 0, line_count = 0;
    unsigned long range_end, cursor;
    FILE *maps;
    int covered = 0;

    if (observer.live_tasks != 1 || length == 0 ||
        length > ULONG_MAX - address ||
        snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", (long)pid) >=
            (int)sizeof(maps_path))
        return 0;
    range_end = address + length;
    cursor = address;
    maps = fopen(maps_path, "r");
    if (maps == NULL) return 0;
    while (getline(&line, &line_capacity, maps) >= 0) {
        unsigned long map_start, map_end;
        char permissions[8] = {0};
        int parsed;

        if (++line_count > 131072) break;
        parsed = sscanf(line, "%lx-%lx %7s", &map_start, &map_end,
                        permissions);
        if (parsed != 3 || map_start >= map_end || strlen(permissions) < 4)
            break;
        if (map_end <= cursor) continue;
        if (map_start > cursor || permissions[3] != 'p') break;
        cursor = map_end < range_end ? map_end : range_end;
        if (cursor == range_end) {
            covered = 1;
            break;
        }
    }
    free(line);
    (void)fclose(maps);
    return covered;
}

static void classify_syscall(long number, const struct user_regs_struct *regs,
                             int entering, struct task_state *task)
{
    long descriptor = (long)regs->rdi;

    switch (number) {
    case 41: /* socket */
    case 42: /* connect */
    case 43: /* accept */
    case 44: /* sendto */
    case 45: /* recvfrom */
    case 46: /* sendmsg */
    case 47: /* recvmsg */
    case 48: /* shutdown */
    case 49: /* bind */
    case 50: /* listen */
    case 51: /* getsockname */
    case 52: /* getpeername */
    case 53: /* socketpair */
    case 54: /* setsockopt */
    case 55: /* getsockopt */
    case 299: /* recvmmsg */
    case 307: /* sendmmsg */
    case 288: /* accept4 */
        observer.saw_network = 1;
        return;
    case 4:  /* stat */
    case 5:  /* fstat */
    case 6:  /* lstat */
    case 21: /* access */
    case 262: /* newfstatat */
    case 269: /* faccessat */
    case 332: /* statx */
    case 439: /* faccessat2 */
        if ((number == 5 && descriptor_is_declared_output(
                                  task, (int)regs->rdi)) ||
            ((number == 4 || number == 6 || number == 21 || number == 262 ||
              number == 269 || number == 332 || number == 439) &&
             path_is_declared_output(task->pending_path))) return;
        observer.saw_metadata = 1;
        return;
    case 78: /* getdents */
    case 217: /* getdents64 */
        if (entering) {
            const char *path = tracked_descriptor(task, (int)descriptor);
            /* Membership hashes are sorted, but the tracee sees native
             * filesystem order. Until the backend normalizes that order,
             * enumeration itself cannot authorize reuse. */
            observer.saw_directory = 1;
            if (path != NULL && descriptor_is_directory(task, (int)descriptor)) {
                if (!path_is_declared_output(path))
                    candidate_path("directory listing", path);
            } else {
                if (path == NULL) observer.saw_external_descriptor = 1;
            }
        }
        return;
    case 80: /* chdir */
    case 81: /* fchdir */
        return;
    case 1:  /* write */
    case 18: /* pwrite64 */
    case 20: /* writev */
    case 77: /* ftruncate */
        if ((number == 1 || number == 20) &&
            (descriptor == STDOUT_FILENO || descriptor == STDERR_FILENO))
            return;
        if (number == 1 || number == 18 || number == 20) {
            const char *path = tracked_descriptor(task, (int)descriptor);
            if (path != NULL && strcmp(path, "/dev/null") == 0) return;
        }
        if (!descriptor_is_declared_output(task, (int)descriptor))
            observer.saw_mutation = 1;
        return;
    case 76: /* truncate */
    case 83: /* mkdir */
    case 84: /* rmdir */
    case 87: /* unlink */
    case 90: /* chmod */
    case 258: /* mkdirat */
    case 263: /* unlinkat */
    case 268: /* fchmodat */
    case 452: /* fchmodat2 */
        if (path_is_declared_output(task->pending_path)) return;
        observer.saw_mutation = 1;
        return;
    case 82: /* rename */
    case 88: /* symlink */
    case 92: /* chown */
    case 93: /* fchown */
    case 264: /* renameat */
    case 265: /* linkat */
    case 266: /* symlinkat */
        observer.saw_mutation = 1;
        return;
    case 91: /* fchmod */
        if (!descriptor_is_declared_output(task, (int)descriptor))
            observer.saw_mutation = 1;
        return;
    case 0:  /* read */
    case 17: /* pread64 */
    case 19: /* readv */
        if (entering) {
            const char *path = descriptor < 0 ? NULL :
                tracked_descriptor(task, (int)descriptor);
            if (path != NULL &&
                descriptor_is_directory(task, (int)descriptor)) {
                if (!path_is_declared_output(path))
                    observer.saw_directory = 1;
            } else if (path != NULL) {
                candidate_path("read descriptor", path);
            } else {
                observer.saw_external_descriptor = 1;
            }
        }
        return;
    case 3: /* close: remove provenance at syscall exit */
        return;
    case 29: /* ioctl */
        reject_unsupported_syscall(number);
        return;
    case 32: /* dup */
    case 33: /* dup2 */
    case 292: /* dup3 */
        if (tracked_descriptor(task, (int)descriptor) == NULL)
            observer.saw_external_descriptor = 1;
        return;
    case 72: /* fcntl */
        if (regs->rsi == F_DUPFD || regs->rsi == F_DUPFD_CLOEXEC) {
            if (tracked_descriptor(task, (int)descriptor) == NULL)
                observer.saw_external_descriptor = 1;
        } else {
            reject_unsupported_syscall(number);
        }
        return;
    case 436: /* close_range */
        return;
    case 9:  /* mmap */
        if (((int)regs->rdx & PROT_WRITE) != 0 &&
            ((int)regs->r10 & MAP_SHARED) != 0) {
            if (!descriptor_is_declared_output(task, (int)regs->r8))
                observer.saw_mutation = 1;
        }
        if (entering && ((int)regs->r10 & MAP_ANONYMOUS) == 0) {
            const char *path = tracked_descriptor(task, (int)regs->r8);
            if (path != NULL)
                candidate_path("mapped file", path);
            else
                observer.saw_external_descriptor = 1;
        }
        return;
    case 10: /* mprotect */
        if (((int)regs->rdx & PROT_WRITE) != 0 &&
            !tracee_range_is_private(task->pid, regs->rdi, regs->rsi))
            observer.saw_mutation = 1;
        return;
    case 202: /* futex: thread synchronization */
    case 12:  /* brk */
    case 13:  /* rt_sigaction */
    case 14:  /* rt_sigprocmask */
    case 15:  /* rt_sigreturn */
    case 24:  /* sched_yield */
    case 25:  /* mremap */
    case 26:  /* msync */
    case 28:  /* madvise */
    case 79:  /* getcwd is covered by working-directory and cwd-change inputs */
    case 2:   /* open: path and flags captured by note_syscall */
    case 257: /* openat: path and flags captured by note_syscall */
    case 11:  /* munmap */
        return;
    case 102: /* getuid */
    case 104: /* getgid */
    case 107: /* geteuid */
    case 108: /* getegid */
        if (!observer.normalized_identity) observer.saw_context = 1;
        return;
    case 110: /* getppid */
    case 111: /* getpgrp */
    case 115: /* getgroups */
    case 117: /* getresuid */
    case 119: /* getresgid */
    case 121: /* getpgid */
    case 124: /* getsid */
    case 186: /* gettid */
    case 204: /* sched_getaffinity exposes host CPU topology */
    case 218: /* set_tid_address returns the volatile caller TID */
    case 39:  /* getpid is a volatile execution-context observation */
    case 302: /* prlimit64 can observe or change resource limits */
        observer.saw_context = 1;
        return;
    case 56:  /* clone: descendants are traced */
        task->shares_descriptors =
            (((unsigned long)regs->rdi & CLONE_FILES) != 0);
        if (task->shares_descriptors) reject_unsupported_syscall(number);
        return;
    case 435: /* clone3: shared descriptor tables are unsupported */
        if (task->shares_descriptors) reject_unsupported_syscall(number);
        return;
    case 57:  /* fork: descendants are traced */
    case 58:  /* vfork: descendants are traced */
    case 59:  /* execve is captured by note_syscall */
    case 89:  /* readlink is captured by note_syscall */
    case 267: /* readlinkat is captured by note_syscall */
    case 322: /* execveat path is captured by note_syscall */
    case 437: /* openat2 request validated by note_syscall */
    case 60:  /* exit */
    case 231: /* exit_group */
    case 273: /* set_robust_list */
    case 318: /* getrandom */
        if (number == 318) {
            reject_unsupported_syscall(number);
        }
        return;
    default:
        reject_unsupported_syscall(number);
        return;
    }
}

#if defined(__linux__) && defined(__x86_64__)
static int tracee_read_word(pid_t pid, uintptr_t address,
                            unsigned long *value)
{
    long result;
    errno = 0;
    result = ptrace(PTRACE_PEEKDATA, pid, (void *)address, NULL);
    if (result == -1 && errno != 0) return -1;
    *value = (unsigned long)result;
    return 0;
}

static int disable_tracee_vdso(pid_t pid)
{
    struct user_regs_struct registers;
    uintptr_t cursor;
    unsigned long argument_count, pointer, type, value;
    size_t index;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &registers) < 0) return -1;
    cursor = (uintptr_t)registers.rsp;
    if (tracee_read_word(pid, cursor, &argument_count) < 0 ||
        argument_count > 131072UL ||
        cursor > UINTPTR_MAX - 2 * sizeof(unsigned long) ||
        argument_count > (UINTPTR_MAX - cursor -
            2 * sizeof(unsigned long)) / sizeof(unsigned long))
        return -1;
    cursor += (argument_count + 1) * sizeof(unsigned long);
    if (tracee_read_word(pid, cursor, &pointer) < 0 || pointer != 0)
        return -1;
    cursor += sizeof(unsigned long);

    for (index = 0; index < 131072; index++) {
        if (tracee_read_word(pid, cursor, &pointer) < 0) return -1;
        cursor += sizeof(unsigned long);
        if (pointer == 0) break;
    }
    if (index == 131072) return -1;

    for (index = 0; index < 256; index++) {
        if (tracee_read_word(pid, cursor, &type) < 0 ||
            tracee_read_word(pid, cursor + sizeof(unsigned long), &value) < 0)
            return -1;
        if (type == AT_NULL) return 0;
        if (type == AT_SYSINFO_EHDR || type == AT_SYSINFO) {
            if (value != 0 && ptrace(PTRACE_POKEDATA, pid,
                    (void *)(cursor + sizeof(unsigned long)), NULL) < 0)
                return -1;
        }
        cursor += 2 * sizeof(unsigned long);
    }
    return -1;
}
#endif

static void syscall_stop(struct task_state *task)
{
    struct user_regs_struct registers;

    if (ptrace(PTRACE_GETREGS, task->pid, NULL, &registers) < 0) {
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        return;
    }
    if (!task->syscall_entry) {
        task->syscall_entry = 1;
        {
            long number = (long)registers.orig_rax;
            if (!task->in_execution_tree) {
                if (!observer.observation_started &&
                    (number == 59 || number == 322))
                    note_syscall(number, &registers, task);
                return;
            }
            if (!observer.observation_started &&
                (number == 59 || number == 322))
                note_syscall(number, &registers, task);
            else {
                note_syscall(number, &registers, task);
                classify_syscall(number, &registers, 1, task);
            }
        }
        return;
    }

    task->syscall_entry = 0;
    if (!observer.observation_started || !task->in_execution_tree) return;
    long result = (long)registers.rax;
    if (observer.normalized_identity &&
        (task->syscall_number == 102 || task->syscall_number == 104 ||
         task->syscall_number == 107 || task->syscall_number == 108) &&
        result != 0)
        observer.saw_context = 1;
    if (task->syscall_number == 3) {
        if (result < 0) mark_unmodeled_error();
        forget_descriptor(task, task->pending_descriptor);
    }
    if ((task->pending_duplication || task->pending_close_range) &&
        result < 0)
        mark_unmodeled_error();
    if ((task->syscall_number == 0 || task->syscall_number == 17 ||
         task->syscall_number == 19 || task->syscall_number == 78 ||
         task->syscall_number == 217) && result < 0)
        mark_unmodeled_error();
    if (task->syscall_number == 9 && result < 0)
        mark_unmodeled_error();
    if ((task->syscall_number == 80 || task->syscall_number == 81) &&
        result < 0)
        mark_unmodeled_error();
    if (task->syscall_number == 89 || task->syscall_number == 267) {
        if (result >= 0)
            candidate_path("symlink", task->pending_path);
        else if (result == -ENOENT || result == -ENOTDIR)
            candidate_path("absent path", task->pending_path);
        else
            mark_unmodeled_error();
        task->pending_path[0] = '\0';
    }
    if (task->pending_duplication && result >= 0) {
        const char *source = tracked_descriptor(task,
                                                task->pending_descriptor);
        int close_on_exec = task->pending_close_on_exec;
        if (task->syscall_number == 33) close_on_exec = 0;
        if (source != NULL &&
            !(task->syscall_number == 33 &&
              result == task->pending_descriptor) &&
            remember_descriptor(task, (int)result,
                close_on_exec ? O_CLOEXEC : 0,
                descriptor_is_directory(task, task->pending_descriptor),
                source) < 0)
            mark_observer_failure();
    }
    if (task->pending_close_range && result == 0) {
        size_t index = 0;
        while (index < task->fd_count) {
            int fd = task->descriptors[index].descriptor;
            if ((unsigned int)fd < task->pending_range_start ||
                (unsigned int)fd > task->pending_range_end) {
                index++;
            } else if (task->pending_close_on_exec) {
                task->descriptors[index].flags |= O_CLOEXEC;
                index++;
            } else {
                forget_descriptor(task, fd);
            }
        }
    }
    if (task->pending_cwd_change) {
        if (result == 0 && task->pending_cwd_is_directory &&
            task->pending_path[0] != '\0')
            candidate_path("cwd change", task->pending_path);
        else
            observer.saw_directory = 1;
    }
    if (task->pending_path[0] != '\0' &&
        (task->syscall_number == 2 || task->syscall_number == 257 ||
         task->syscall_number == 437)) {
        if (result >= 0) {
            int access_mode = (int)(task->flags & O_ACCMODE);
            int is_directory = (task->flags & O_DIRECTORY) != 0;
            if (remember_descriptor(task, (int)result, task->flags,
                                    is_directory, task->pending_path) < 0) {
                mark_observer_failure();
            }
            if (access_mode == O_RDONLY && (task->flags & O_PATH) == 0 &&
                (task->flags & (O_TRUNC | O_CREAT | O_APPEND)) == 0) {
                candidate_path(is_directory ? "opened directory" :
                                                "opened file",
                               task->pending_path);
            } else if ((task->flags & O_PATH) != 0 &&
                       !path_is_declared_output(task->pending_path)) {
                observer.saw_metadata = 1;
            } else if (strcmp(task->pending_path, "/dev/null") != 0 &&
                       !path_is_declared_output(task->pending_path)) {
                observer.saw_mutation = 1;
            }
        } else if (result == -ENOENT || result == -ENOTDIR) {
            candidate_path("absent path", task->pending_path);
        } else {
            mark_unmodeled_error();
        }
        task->pending_path[0] = '\0';
    } else if (task->pending_path[0] != '\0' &&
               (task->syscall_number == 59 ||
                task->syscall_number == 322) && result < 0) {
        if (result == -ENOENT || result == -ENOTDIR) {
            candidate_path("absent executable", task->pending_path);
        } else mark_unmodeled_error();
        task->pending_path[0] = '\0';
    } else {
        task->pending_path[0] = '\0';
    }
}

static void report_reasons(void)
{
    if (observer.controlled_runtime) {
        fprintf(stderr,
            "tm: RUN: controlled profile observation active; reuse requires complete observation and trusted evidence\n");
    } else {
        fprintf(stderr,
            "tm: RUN: observer prototype; cache reuse is disabled\n");
    }
    if (observer.saw_network) {
        fprintf(stderr, "tm: reuse rejected: socket or network operation observed\n");
    }
    if (observer.saw_mutation) {
        fprintf(stderr, "tm: reuse rejected: filesystem mutation observed\n");
    }
    if (observer.saw_metadata) {
        fprintf(stderr, "tm: reuse rejected: filesystem metadata observation is not modeled\n");
    }
    if (observer.saw_directory) {
        fprintf(stderr,
            "tm: reuse rejected: directory enumeration uses native filesystem ordering\n");
    }
    if (observer.saw_external_descriptor) {
        fprintf(stderr, "tm: reuse rejected: inherited or untracked descriptor provenance is not modeled\n");
    }
    if (observer.saw_external_path) {
        fprintf(stderr, "tm: reuse rejected: external filesystem path is outside the repository input model\n");
    }
    if (observer.saw_unmodeled_error) {
        fprintf(stderr,
            "tm: reuse rejected: filesystem or descriptor error result is not modeled\n");
    }
    if (observer.saw_context) {
        fprintf(stderr,
            "tm: reuse rejected: process identity, credentials, CPU affinity, or resource limits are not part of the verified context\n");
    }
    if (observer.saw_unknown_syscall) {
        size_t unsupported_index;
        fprintf(stderr, "tm: reuse rejected: unsupported syscall(s):");
        for (unsupported_index = 0;
             unsupported_index < observer.unsupported_count;
             unsupported_index++) {
            fprintf(stderr, " %ld", observer.unsupported_syscalls[unsupported_index]);
        }
        if (observer.saw_observer_failure) {
            fprintf(stderr, " (observer failure)");
        }
        fprintf(stderr, "\n");
    }
}

static int plain_wait(pid_t child)
{
    int status;

    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("tm: waitpid");
            return TM_EXIT_INTERNAL_ERROR;
        }
        forward_pending_signal(child);
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return TM_EXIT_INTERNAL_ERROR;
}

static int collect_traced_child(pid_t child)
{
    int status;

    for (;;) {
        pid_t waited = waitpid(child, &status, __WALL);
        if (waited < 0) {
            if (errno == EINTR) {
                forward_pending_signal(child);
                continue;
            }
            perror("tm: waitpid after observer failure");
            return TM_EXIT_INTERNAL_ERROR;
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        }
        if (WIFSTOPPED(status)) {
            int signal_number = WSTOPSIG(status);
            if (signal_number == SIGSTOP || signal_number == SIGTRAP ||
                signal_number == (SIGTRAP | 0x80)) {
                signal_number = 0;
            }
            (void)ptrace(PTRACE_CONT, child, NULL,
                         (void *)(long)signal_number);
        }
    }
}

static int descriptor_is_preserved(const int *preserved, size_t count,
                                   int descriptor)
{
    size_t index;
    for (index = 0; index < count; index++)
        if (preserved[index] == descriptor) return 1;
    return 0;
}

static int close_unpreserved_descriptors(const int *preserved, size_t count)
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int scan_descriptor;
    if (directory == NULL) return count == 0 ? 0 : -1;
    scan_descriptor = dirfd(directory);
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        long descriptor;
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        descriptor = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || descriptor <= STDERR_FILENO ||
            descriptor == scan_descriptor || descriptor > INT32_MAX ||
            descriptor_is_preserved(preserved, count, (int)descriptor))
            continue;
        (void)close((int)descriptor);
    }
    if (closedir(directory) < 0) return -1;
    for (size_t index = 0; index < count; index++) {
        int flags = fcntl(preserved[index], F_GETFD);
        if (flags < 0 || fcntl(preserved[index], F_SETFD,
                               flags & ~FD_CLOEXEC) < 0) return -1;
    }
    return 0;
}

static void exec_command(char **command, char *const environment[],
                         const int *preserved_fds,
                         size_t preserved_fd_count)
{
    if (close_unpreserved_descriptors(preserved_fds, preserved_fd_count) < 0)
        _exit(TM_EXIT_INTERNAL_ERROR);
    if (environment != NULL) environ = (char **)environment;
    execvp(command[0], command);
    if (errno == ENOENT || errno == ENOTDIR) {
        fprintf(stderr, "tm: command not found: %s\n", command[0]);
        _exit(TM_EXIT_COMMAND_NOT_FOUND);
    }
    fprintf(stderr, "tm: cannot execute %s: %s\n", command[0],
            strerror(errno));
    _exit(TM_EXIT_CANNOT_EXECUTE);
}

static void resume_task(pid_t pid, int signal_number)
{
    if (ptrace(PTRACE_SYSCALL, pid, NULL,
               (void *)(long)signal_number) < 0 && errno != ESRCH) {
        int saved_error = errno;
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        fprintf(stderr, "tm: observer could not resume process %ld: %s\n",
                (long)pid, strerror(saved_error));
        (void)ptrace(PTRACE_CONT, pid, NULL, (void *)(long)signal_number);
    }
}

static void detach_descendants(void)
{
    size_t index;
    int has_tasks = 0;
    int has_application_descendants = 0;

    for (index = 0; index < TM_MAX_TASKS; index++) {
        if (tasks[index].active && tasks[index].pid != observer.direct_pid) {
            has_tasks = 1;
            if (tasks[index].in_execution_tree)
                has_application_descendants = 1;
        }
    }
    if (!has_tasks) return;
    if (has_application_descendants) {
        observer.saw_outliving_descendant = 1;
        fprintf(stderr,
                "tm: reuse rejected: descendant outlived the command\n");
    }
    for (index = 0; index < TM_MAX_TASKS; index++) {
        if (tasks[index].active && tasks[index].pid != observer.direct_pid) {
            (void)kill(tasks[index].pid, SIGSTOP);
        }
    }
    for (index = 0; index < TM_MAX_TASKS; index++) {
        int status;
        pid_t waited;
        unsigned int attempts;

        if (!tasks[index].active || tasks[index].pid == observer.direct_pid) {
            continue;
        }
        waited = 0;
        for (attempts = 0; attempts < 50 && waited == 0; attempts++) {
            waited = waitpid(tasks[index].pid, &status, __WALL | WNOHANG);
            if (waited == 0) {
                usleep(1000);
            }
        }
        if (waited == tasks[index].pid && WIFSTOPPED(status)) {
            (void)ptrace(PTRACE_DETACH, tasks[index].pid, NULL, NULL);
        }
        {
            size_t descriptor_index;
            for (descriptor_index = 0;
                 descriptor_index < tasks[index].fd_count;
                 descriptor_index++)
                free(tasks[index].descriptors[descriptor_index].path);
            tasks[index].fd_count = 0;
        }
        tasks[index].active = 0;
    }
    /* Resume only after every tracee is detached. Delivering SIGCONT while
     * other tracees still have a pending SIGSTOP can leave them stopped. */
    for (index = 0; index < TM_MAX_TASKS; index++) {
        if (tasks[index].pid != observer.direct_pid)
            (void)kill(tasks[index].pid, SIGCONT);
    }
}

static void mark_report_observer_failure(struct tm_observer_report *report)
{
    if (report == NULL) return;
    report->observation_complete = 0;
    report->stable_input_view = 0;
    report->ineligibility_reasons |=
        TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE |
        TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW;
}

static int target_executable_matches(const char *target, const char *observed)
{
    const char *base;
    if (target == NULL || observed == NULL) return 0;
    if (strcmp(target, observed) == 0) return 1;
    if (strchr(target, '/') != NULL) return 0;
    base = strrchr(observed, '/');
    return strcmp(base == NULL ? observed : base + 1, target) == 0;
}

static int trace_child(pid_t child, int explain, const char *repository_root,
                       int inherited_descriptors,
                       const char *start_after_exec,
                       int controlled_runtime, int normalized_identity,
                       const char *const *output_roots,
                       size_t output_root_count,
                       struct tm_observer_report *report)
{
    int status;
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT |
                   PTRACE_O_EXITKILL;
    pid_t waited;

    memset(tasks, 0, sizeof(tasks));
    memset(&observer, 0, sizeof(observer));
    observer.explain = explain;
    observer.repository_root = repository_root;
    observer.controlled_runtime = controlled_runtime;
    observer.normalized_identity = normalized_identity && controlled_runtime;
    observer.output_roots = output_roots;
    observer.output_root_count = output_root_count;
    observer.start_after_exec = start_after_exec;
    observer.observation_started = start_after_exec == NULL;
    observer.saw_external_descriptor = inherited_descriptors;
    observer.direct_pid = child;
    {
        struct task_state *initial_task = add_task(child);
        if (initial_task == NULL) {
            mark_report_observer_failure(report);
            return plain_wait(child);
        }
        initial_task->in_execution_tree = start_after_exec == NULL;
    }
    do {
        waited = waitpid(child, &status, 0);
        if (waited < 0 && errno == EINTR) forward_pending_signal(child);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        mark_report_observer_failure(report);
        perror("tm: observer waitpid");
        return collect_traced_child(child);
    }
    if (WIFEXITED(status)) {
        mark_report_observer_failure(report);
        if (explain) {
            fprintf(stderr,
                    "tm: RUN: ptrace setup unavailable; command completed uncached\n");
        }
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        mark_report_observer_failure(report);
        return 128 + WTERMSIG(status);
    }
    if (!WIFSTOPPED(status)) {
        observer.saw_unknown_syscall = 1;
        mark_report_observer_failure(report);
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)options) < 0) {
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        mark_report_observer_failure(report);
        if (explain) {
            fprintf(stderr, "tm: RUN: ptrace setup failed; executing uncached\n");
        }
        if (ptrace(PTRACE_DETACH, child, NULL, (void *)(long)SIGCONT) == 0) {
            return plain_wait(child);
        }
        (void)ptrace(PTRACE_CONT, child, NULL, (void *)(long)SIGCONT);
        return collect_traced_child(child);
    }
    forward_pending_signal(child);
    resume_task(child, 0);

    while (observer.live_tasks > 0) {
        forward_pending_signal(child);
        pid_t pid = waitpid(-1, &status, __WALL);
        struct task_state *task;
        unsigned int event;
        int stop_signal;

        if (pid < 0) {
            if (errno == EINTR) {
                forward_pending_signal(child);
                continue;
            }
            observer.saw_unknown_syscall = 1;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            finish_task(pid, status);
            if (observer.direct_finished) {
                if (received_wrapper_signal == 0) {
                    detach_descendants();
                    break;
                }
                for (size_t index = 0; index < TM_MAX_TASKS; index++)
                    if (tasks[index].active &&
                        tasks[index].pid != observer.direct_pid)
                        (void)kill(tasks[index].pid, SIGKILL);
            }
            continue;
        }
        if (!WIFSTOPPED(status)) {
            observer.saw_unknown_syscall = 1;
            continue;
        }

        task = find_task(pid);
        if (task == NULL) {
            task = add_task(pid);
        }
        if (task == NULL) {
            observer.saw_unknown_syscall = 1;
            (void)ptrace(PTRACE_CONT, pid, NULL, NULL);
            continue;
        }
        if (observer.direct_finished && received_wrapper_signal != 0 &&
            pid != observer.direct_pid)
            (void)kill(pid, SIGKILL);
        event = (unsigned int)status >> 16;
        stop_signal = WSTOPSIG(status);
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long child_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid) == 0) {
                struct task_state *new_task = add_task((pid_t)child_pid);
                if (new_task == NULL) {
                    observer.saw_unknown_syscall = 1;
                } else {
                    /* The child's first syscall-stop is its next entry; the
                     * parent-side clone event does not produce a child exit
                     * stop that should advance this phase. */
                    new_task->syscall_entry = 0;
                    new_task->in_execution_tree = task->in_execution_tree;
                    if (event != PTRACE_EVENT_CLONE ||
                        !task->shares_descriptors) {
                        if (copy_descriptors(new_task, task) < 0)
                            mark_observer_failure();
                    }
                }
            }
        } else if (event == PTRACE_EVENT_EXEC) {
            if (!observer.observation_started) {
                if ((task->syscall_number == 59 ||
                     task->syscall_number == 322) &&
                    target_executable_matches(observer.start_after_exec,
                                              task->pending_path)) {
                    observer.observation_started = 1;
                    task->in_execution_tree = 1;
                    candidate_path("executable", task->pending_path);
                    if (observer.controlled_runtime &&
                        remember_descriptor(task, STDIN_FILENO, O_RDONLY,
                                            0, "/dev/null") < 0)
                        mark_observer_failure();
                }
            } else if ((task->syscall_number == 59 ||
                        task->syscall_number == 322) &&
                       task->pending_path[0] != '\0') {
                candidate_path("executable", task->pending_path);
            }
#if defined(__linux__) && defined(__x86_64__)
            if (observer.observation_started && task->in_execution_tree &&
                disable_tracee_vdso(pid) < 0)
                mark_observer_failure();
#endif
            forget_cloexec_descriptors(task);
        }
        if (stop_signal == (SIGTRAP | 0x80)) {
            syscall_stop(task);
            resume_task(pid, 0);
        } else if (event != 0) {
            resume_task(pid, 0);
        } else if (stop_signal == SIGSTOP || stop_signal == SIGTRAP) {
            resume_task(pid, 0);
        } else {
            resume_task(pid, stop_signal);
        }
    }

    if (!observer.direct_finished) {
        mark_report_observer_failure(report);
        return collect_traced_child(child);
    }
    copy_candidate_report(report);
    if (!observer.observation_started) {
        observer.saw_observer_failure = 1;
        observer.saw_unknown_syscall = 1;
        if (report != NULL) {
            report->ineligibility_reasons |=
                TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE |
                TM_OBSERVER_INELIGIBLE_UNSUPPORTED;
        }
    }
    if (explain) {
        report_reasons();
    }
    if (report != NULL) {
        if (observer.saw_network)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_NETWORK;
        if (observer.saw_mutation)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_MUTATION;
        if (observer.saw_metadata)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_METADATA;
        if (observer.saw_directory)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_DIRECTORY;
        if (observer.saw_external_descriptor)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_DESCRIPTOR;
        if (observer.saw_unknown_syscall)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_UNSUPPORTED;
        if (observer.saw_observer_failure)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE;
        if (observer.saw_outliving_descendant)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_DESCENDANT;
        if (observer.saw_external_path)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT;
        if (observer.saw_unmodeled_error)
            report->ineligibility_reasons |=
                TM_OBSERVER_INELIGIBLE_UNMODELED_ERROR;
        if (observer.saw_context)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_CONTEXT;
        report->stable_input_view = observer.controlled_runtime;
        if (!report->stable_input_view)
            report->ineligibility_reasons |= TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW;
        else
            report->ineligibility_reasons &=
                ~TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW;
        report->observation_complete = !observer.saw_observer_failure &&
            !observer.saw_outliving_descendant;
    }
    if (WIFEXITED(observer.direct_status)) {
        return WEXITSTATUS(observer.direct_status);
    }
    if (WIFSIGNALED(observer.direct_status)) {
        return 128 + WTERMSIG(observer.direct_status);
    }
    return TM_EXIT_INTERNAL_ERROR;
}

int tm_observe_and_run_with_fds_identity(char **command, int explain,
                                char *const environment[],
                                const char *repository_root,
                                const int *preserved_fds,
                                size_t preserved_fd_count,
                                int null_stdin, int set_umask_022,
                                const char *start_after_exec,
                                int controlled_runtime,
                                int normalized_identity,
                                const char *const *output_roots,
                                size_t output_root_count,
                                struct tm_observer_report *report)
{
    struct sigaction previous[TM_FORWARDED_SIGNAL_COUNT];
    int inherited_descriptors = has_inherited_descriptors();
    pid_t child;
    int result;

    if (report != NULL) memset(report, 0, sizeof(*report));

    if (install_signal_forwarding(previous) < 0) {
        perror("tm: install signal forwarding");
        return TM_EXIT_INTERNAL_ERROR;
    }
    child = fork();

    if (child < 0) {
        perror("tm: fork");
        restore_signal_handlers(previous);
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (child == 0) {
        restore_signal_handlers(previous);
        if (close_unpreserved_descriptors(preserved_fds,
                                          preserved_fd_count) < 0)
            _exit(TM_EXIT_INTERNAL_ERROR);
        if (set_umask_022) (void)umask(022);
        if (null_stdin) {
            int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0)
                _exit(TM_EXIT_INTERNAL_ERROR);
            if (null_fd != STDIN_FILENO) close(null_fd);
        }
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            if (explain) {
                fprintf(stderr,
                        "tm: observer unavailable: %s; running uncached\n",
                        strerror(errno));
            }
            exec_command(command, environment, preserved_fds,
                         preserved_fd_count);
        }
        raise(SIGSTOP);
        exec_command(command, environment, preserved_fds,
                     preserved_fd_count);
    }
    result = trace_child(child, explain, repository_root,
                         inherited_descriptors, start_after_exec,
                         controlled_runtime, normalized_identity,
                         output_roots, output_root_count,
                         report);
    restore_signal_handlers(previous);
    return result;
}

int tm_observe_and_run_with_fds(char **command, int explain,
                                char *const environment[],
                                const char *repository_root,
                                const int *preserved_fds,
                                size_t preserved_fd_count,
                                int null_stdin, int set_umask_022,
                                const char *start_after_exec,
                                int controlled_runtime,
                                const char *const *output_roots,
                                size_t output_root_count,
                                struct tm_observer_report *report)
{
    return tm_observe_and_run_with_fds_identity(command, explain, environment,
        repository_root, preserved_fds, preserved_fd_count, null_stdin,
        set_umask_022, start_after_exec, controlled_runtime, 0, output_roots,
        output_root_count, report);
}

int tm_observe_and_run(char **command, int explain, char *const environment[],
                       const char *repository_root,
                       struct tm_observer_report *report)
{
    const char *start_after_exec = command != NULL ? command[0] : NULL;
    char *working_directory = NULL, *resolved_target = NULL;
    int result;

    if (start_after_exec != NULL && start_after_exec[0] != '/' &&
        strchr(start_after_exec, '/') != NULL) {
        working_directory = getcwd(NULL, 0);
        if (working_directory != NULL) {
            size_t directory_length = strlen(working_directory);
            size_t target_length = strlen(start_after_exec);
            if (directory_length <= SIZE_MAX - 2 &&
                target_length <= SIZE_MAX - directory_length - 2) {
                resolved_target = malloc(directory_length + target_length + 2);
                if (resolved_target != NULL) {
                    memcpy(resolved_target, working_directory,
                           directory_length);
                    resolved_target[directory_length] = '/';
                    memcpy(resolved_target + directory_length + 1,
                           start_after_exec, target_length + 1);
                    start_after_exec = resolved_target;
                } else {
                    start_after_exec = NULL;
                }
            } else {
                start_after_exec = NULL;
            }
        } else {
            start_after_exec = NULL;
        }
    }
    result = tm_observe_and_run_with_fds(command, explain, environment,
        repository_root, NULL, 0, 0, 0, start_after_exec, 0, NULL, 0, report);
    free(resolved_target);
    free(working_directory);
    return result;
}

#else

int tm_observe_and_run_with_fds_identity(char **command, int explain,
                                char *const environment[],
                                const char *repository_root,
                                const int *preserved_fds,
                                size_t preserved_fd_count,
                                int null_stdin, int set_umask_022,
                                const char *start_after_exec,
                                int controlled_runtime,
                                int normalized_identity,
                                const char *const *output_roots,
                                size_t output_root_count,
                                struct tm_observer_report *report)
{
    pid_t child = fork();
    int status;
    (void)repository_root;
    (void)preserved_fds;
    (void)preserved_fd_count;
    (void)null_stdin;
    (void)set_umask_022;
    (void)start_after_exec;
    (void)controlled_runtime;
    (void)normalized_identity;
    (void)output_roots;
    (void)output_root_count;
    if (report != NULL) memset(report, 0, sizeof(*report));
    if (environment != NULL) environ = (char **)environment;

    if (explain) {
        fprintf(stderr,
                "tm: RUN: syscall observer unsupported on this platform; cache reuse is disabled\n");
    }
    if (child < 0) {
        perror("tm: fork");
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (child == 0) {
        execvp(command[0], command);
        _exit(errno == ENOENT ? TM_EXIT_COMMAND_NOT_FOUND :
              TM_EXIT_CANNOT_EXECUTE);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return TM_EXIT_INTERNAL_ERROR;
        }
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return WIFSIGNALED(status) ? 128 + WTERMSIG(status) :
                                TM_EXIT_INTERNAL_ERROR;
}

int tm_observe_and_run_with_fds(char **command, int explain,
                                char *const environment[],
                                const char *repository_root,
                                const int *preserved_fds,
                                size_t preserved_fd_count,
                                int null_stdin, int set_umask_022,
                                const char *start_after_exec,
                                int controlled_runtime,
                                const char *const *output_roots,
                                size_t output_root_count,
                                struct tm_observer_report *report)
{
    return tm_observe_and_run_with_fds_identity(command, explain, environment,
        repository_root, preserved_fds, preserved_fd_count, null_stdin,
        set_umask_022, start_after_exec, controlled_runtime, 0, output_roots,
        output_root_count, report);
}

int tm_observe_and_run(char **command, int explain, char *const environment[],
                       const char *repository_root,
                       struct tm_observer_report *report)
{
    return tm_observe_and_run_with_fds(command, explain, environment,
                                       repository_root, NULL, 0, 0, 0, NULL,
                                       0, NULL, 0, report);
}

#endif
