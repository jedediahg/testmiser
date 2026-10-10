#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__) && defined(__x86_64__)
#include <linux/openat2.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#endif

#include "tm/observer.h"
#include "tm/tm.h"

extern char **environ;

#if defined(__linux__) && defined(__x86_64__)

#define TM_MAX_TASKS 4096
#define TM_PATH_SIZE 1024
#define TM_MAX_CANDIDATES 512
#define TM_MAX_UNSUPPORTED 32
#define TM_MAX_DESCRIPTORS 128

struct fd_entry {
    int descriptor;
    unsigned long flags;
    char *path;
};

struct task_state {
    pid_t pid;
    int active;
    int syscall_entry;
    long syscall_number;
    unsigned long flags;
    int shares_descriptors;
    int pending_descriptor;
    char pending_path[TM_PATH_SIZE];
    size_t fd_count;
    struct fd_entry descriptors[TM_MAX_DESCRIPTORS];
};

struct observer_state {
    int explain;
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
    size_t candidate_count;
    size_t unsupported_count;
    long unsupported_syscalls[TM_MAX_UNSUPPORTED];
    char candidates[TM_MAX_CANDIDATES][TM_PATH_SIZE + 32];
};

static struct task_state tasks[TM_MAX_TASKS];
static struct observer_state observer;

static void mark_observer_failure(void)
{
    observer.saw_unknown_syscall = 1;
    observer.saw_observer_failure = 1;
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

static int remember_descriptor(struct task_state *task, int fd,
                               unsigned long flags, const char *path)
{
    char *copy;
    if (fd < 0 || fd > 1048576 || path == NULL) return -1;
    copy = strdup(path);
    if (copy == NULL) return -1;
    forget_descriptor(task, fd);
    if (task->fd_count == TM_MAX_DESCRIPTORS) {
        free(copy);
        return -1;
    }
    task->descriptors[task->fd_count].descriptor = fd;
    task->descriptors[task->fd_count].flags = flags;
    task->descriptors[task->fd_count].path = copy;
    task->fd_count++;
    return 0;
}

static int copy_descriptors(struct task_state *destination,
                            const struct task_state *source)
{
    size_t index;
    for (index = 0; index < source->fd_count; index++)
        if (remember_descriptor(destination,
                source->descriptors[index].descriptor,
                source->descriptors[index].flags,
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
    size_t index;

    if (!observer.explain) {
        return;
    }
    snprintf(candidate, sizeof(candidate), "%s: %s", kind, path);
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
    case 267: /* readlinkat */
    case 322: /* execveat */
        if (read_tracee_string(task->pid, registers->rsi, raw_path,
                               sizeof(raw_path)) == 0) {
            task_path(task->pid, (int)registers->rdi, raw_path,
                      task->pending_path, sizeof(task->pending_path));
            candidate_path(number == 322 ? "executable" : "symlink",
                           task->pending_path);
        } else {
            mark_observer_failure();
        }
        return;
    case 437: { /* openat2 */
        struct open_how how;
        const uint64_t allowed_flags = O_RDONLY | O_CLOEXEC | O_LARGEFILE;
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
            candidate_path("executable", task->pending_path);
        } else {
            mark_observer_failure();
        }
        return;
    case 3: /* close */
        task->pending_descriptor = (int)registers->rdi;
        if (task->pending_descriptor < 3 ||
            tracked_descriptor(task, task->pending_descriptor) == NULL)
            observer.saw_external_descriptor = 1;
        return;
    default:
        return;
    }
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
    case 53: /* socketpair */
    case 288: /* accept4 */
        observer.saw_network = 1;
        return;
    case 5:  /* fstat */
    case 21: /* access */
    case 79: /* getcwd is tracked through cwd changes only in a later stage */
    case 262: /* newfstatat */
    case 269: /* faccessat */
    case 332: /* statx */
    case 439: /* faccessat2 */
        observer.saw_metadata = 1;
        return;
    case 78: /* getdents */
    case 217: /* getdents64 */
        observer.saw_directory = 1;
        return;
    case 1:  /* write */
    case 18: /* pwrite64 */
    case 20: /* writev */
    case 76: /* truncate */
    case 77: /* ftruncate */
    case 82: /* rename */
    case 83: /* mkdir */
    case 84: /* rmdir */
    case 87: /* unlink */
    case 88: /* symlink */
    case 90: /* chmod */
    case 91: /* fchmod */
    case 92: /* chown */
    case 93: /* fchown */
    case 263: /* unlinkat */
    case 264: /* renameat */
    case 265: /* linkat */
    case 266: /* symlinkat */
    case 258: /* mkdirat */
        if ((number == 1 || number == 20) &&
            (descriptor == STDOUT_FILENO || descriptor == STDERR_FILENO)) {
            return;
        }
        observer.saw_mutation = 1;
        return;
    case 0:  /* read */
    case 17: /* pread64 */
    case 19: /* readv */
        if (entering) {
            const char *path = descriptor < 3 ? NULL :
                tracked_descriptor(task, (int)descriptor);
            if (path != NULL)
                candidate_path("read descriptor", path);
            else
                observer.saw_external_descriptor = 1;
        }
        return;
    case 3: /* close: remove provenance at syscall exit */
        return;
    case 29: /* ioctl */
    case 32: /* dup */
    case 33: /* dup2 */
    case 72: /* fcntl */
        reject_unsupported_syscall(number);
        return;
    case 9:  /* mmap */
        if (((int)regs->rdx & PROT_WRITE) != 0 &&
            ((int)regs->r10 & MAP_SHARED) != 0) {
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
    case 202: /* futex: thread synchronization */
    case 12:  /* brk */
    case 13:  /* rt_sigaction */
    case 14:  /* rt_sigprocmask */
    case 15:  /* rt_sigreturn */
    case 24:  /* sched_yield */
    case 25:  /* mremap */
    case 26:  /* msync */
    case 28:  /* madvise */
    case 39:  /* getpid */
    case 2:   /* open: path and flags captured by note_syscall */
    case 257: /* openat: path and flags captured by note_syscall */
    case 10:  /* mprotect */
    case 11:  /* munmap */
    case 218: /* set_tid_address */
        return;
    case 56:  /* clone: descendants are traced */
        task->shares_descriptors =
            (((unsigned long)regs->rdi & CLONE_FILES) != 0);
        if (task->shares_descriptors) reject_unsupported_syscall(number);
        return;
    case 57:  /* fork: descendants are traced */
    case 58:  /* vfork: descendants are traced */
    case 59:  /* execve is captured by note_syscall */
    case 437: /* openat2 request validated by note_syscall */
    case 60:  /* exit */
    case 231: /* exit_group */
    case 273: /* set_robust_list */
    case 302: /* prlimit64 */
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
        note_syscall((long)registers.orig_rax, &registers, task);
        classify_syscall((long)registers.orig_rax, &registers, 1, task);
        return;
    }

    task->syscall_entry = 0;
    long result = (long)registers.rax;
    if (task->syscall_number == 3) {
        forget_descriptor(task, task->pending_descriptor);
    }
    if (task->pending_path[0] != '\0' &&
        (task->syscall_number == 2 || task->syscall_number == 257 ||
         task->syscall_number == 437)) {
        if (result >= 0) {
            int access_mode = (int)(task->flags & O_ACCMODE);
            if (remember_descriptor(task, (int)result, task->flags,
                                    task->pending_path) < 0) {
                mark_observer_failure();
            }
            if (access_mode == O_RDONLY && (task->flags & O_PATH) == 0 &&
                (task->flags & (O_TRUNC | O_CREAT | O_APPEND)) == 0) {
                candidate_path("opened file", task->pending_path);
            } else if ((task->flags & O_PATH) != 0) {
                observer.saw_metadata = 1;
            } else {
                observer.saw_mutation = 1;
            }
        } else if (result == -ENOENT || result == -ENOTDIR) {
            candidate_path("absent path", task->pending_path);
        }
        task->pending_path[0] = '\0';
    } else if (task->pending_path[0] != '\0' &&
               (task->syscall_number == 59 ||
                task->syscall_number == 322) && result < 0) {
        if (result == -ENOENT || result == -ENOTDIR) {
            candidate_path("absent executable", task->pending_path);
        }
        task->pending_path[0] = '\0';
    } else {
        task->pending_path[0] = '\0';
    }
}

static void report_reasons(void)
{
    size_t index;

    fprintf(stderr,
            "tm: RUN: observer prototype; cache reuse is disabled\n");
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
        fprintf(stderr, "tm: reuse rejected: directory membership is not modeled\n");
    }
    if (observer.saw_external_descriptor) {
        fprintf(stderr, "tm: reuse rejected: input descriptor provenance is not modeled\n");
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
    for (index = 0; index < observer.candidate_count; index++) {
        fprintf(stderr, "tm: observed input candidate: %s\n",
                observer.candidates[index]);
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

static void exec_command(char **command, char *const environment[])
{
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
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        (void)ptrace(PTRACE_CONT, pid, NULL, (void *)(long)signal_number);
    }
}

static void detach_descendants(void)
{
    size_t index;

    if (observer.live_tasks == 0) {
        return;
    }
    fprintf(stderr, "tm: reuse rejected: descendant outlived the command\n");
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
            (void)ptrace(PTRACE_DETACH, tasks[index].pid, NULL,
                         (void *)(long)SIGCONT);
        } else {
            (void)kill(tasks[index].pid, SIGCONT);
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
}

static int trace_child(pid_t child, int explain)
{
    int status;
    long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;
    pid_t waited;

    memset(tasks, 0, sizeof(tasks));
    memset(&observer, 0, sizeof(observer));
    observer.explain = explain;
    observer.direct_pid = child;
    if (add_task(child) == NULL) {
        return plain_wait(child);
    }
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        perror("tm: observer waitpid");
        return collect_traced_child(child);
    }
    if (WIFEXITED(status)) {
        if (explain) {
            fprintf(stderr,
                    "tm: RUN: ptrace setup unavailable; command completed uncached\n");
        }
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    if (!WIFSTOPPED(status)) {
        observer.saw_unknown_syscall = 1;
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)options) < 0) {
        observer.saw_unknown_syscall = 1;
        observer.saw_observer_failure = 1;
        if (explain) {
            fprintf(stderr, "tm: RUN: ptrace setup failed; executing uncached\n");
        }
        if (ptrace(PTRACE_DETACH, child, NULL, (void *)(long)SIGCONT) == 0) {
            return plain_wait(child);
        }
        (void)ptrace(PTRACE_CONT, child, NULL, (void *)(long)SIGCONT);
        return collect_traced_child(child);
    }
    resume_task(child, 0);

    while (observer.live_tasks > 0) {
        pid_t pid = waitpid(-1, &status, __WALL);
        struct task_state *task;
        unsigned int event;
        int stop_signal;

        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            observer.saw_unknown_syscall = 1;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            finish_task(pid, status);
            if (observer.direct_finished) {
                detach_descendants();
                break;
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
                    new_task->syscall_entry = 1;
                    if (event != PTRACE_EVENT_CLONE ||
                        !task->shares_descriptors) {
                        if (copy_descriptors(new_task, task) < 0)
                            mark_observer_failure();
                    }
                }
            }
        } else if (event == PTRACE_EVENT_EXEC) {
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
        return collect_traced_child(child);
    }
    if (explain) {
        report_reasons();
    }
    if (WIFEXITED(observer.direct_status)) {
        return WEXITSTATUS(observer.direct_status);
    }
    if (WIFSIGNALED(observer.direct_status)) {
        return 128 + WTERMSIG(observer.direct_status);
    }
    return TM_EXIT_INTERNAL_ERROR;
}

int tm_observe_and_run(char **command, int explain, char *const environment[])
{
    pid_t child = fork();

    if (child < 0) {
        perror("tm: fork");
        return TM_EXIT_INTERNAL_ERROR;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            if (explain) {
                fprintf(stderr,
                        "tm: observer unavailable: %s; running uncached\n",
                        strerror(errno));
            }
            exec_command(command, environment);
        }
        raise(SIGSTOP);
        exec_command(command, environment);
    }
    return trace_child(child, explain);
}

#else

int tm_observe_and_run(char **command, int explain, char *const environment[])
{
    pid_t child = fork();
    int status;
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

#endif
