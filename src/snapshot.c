#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/snapshot.h"

#define SNAPSHOT_ENTRY_LIMIT 100000U
#define SNAPSHOT_DEPTH_LIMIT 128U
#define SNAPSHOT_PATH_LIMIT 4096U
#define SNAPSHOT_BYTE_LIMIT (UINT64_C(4) * 1024U * 1024U * 1024U)

struct snapshot_entry {
    char *path;
    struct stat status;
    char digest[65];
    char *link_target;
};

struct inventory {
    struct snapshot_entry *entries;
    size_t count;
};

struct copy_budget {
    uint64_t bytes;
};

struct tm_snapshot {
    char *path;
    int directory_fd;
    size_t root_count;
    int *directory_fds;
    size_t directory_fd_count;
};

static int retain_directory(struct tm_snapshot *snapshot, int directory_fd)
{
    int *resized;
    int copy = fcntl(directory_fd, F_DUPFD_CLOEXEC, 3);
    if (copy < 0) return -1;
    resized = realloc(snapshot->directory_fds,
        (snapshot->directory_fd_count + 1) * sizeof(*snapshot->directory_fds));
    if (resized == NULL) { close(copy); return -1; }
    snapshot->directory_fds = resized;
    snapshot->directory_fds[snapshot->directory_fd_count++] = copy;
    return 0;
}

static int same_version(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
        left->st_mode == right->st_mode && left->st_uid == right->st_uid &&
        left->st_gid == right->st_gid && left->st_nlink == right->st_nlink &&
        left->st_size == right->st_size &&
        left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
        left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
        left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
        left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static void inventory_clear(struct inventory *inventory)
{
    size_t index;
    for (index = 0; index < inventory->count; index++) {
        free(inventory->entries[index].path);
        free(inventory->entries[index].link_target);
    }
    free(inventory->entries);
    memset(inventory, 0, sizeof(*inventory));
}

static int inventory_add(struct inventory *inventory, const char *path,
                         const struct stat *status, const char *digest,
                         const char *link_target)
{
    struct snapshot_entry *resized;
    if (inventory->count >= SNAPSHOT_ENTRY_LIMIT) {
        errno = E2BIG;
        return -1;
    }
    if (status->st_uid != geteuid() || status->st_gid != getegid() ||
        (!S_ISDIR(status->st_mode) && status->st_nlink != 1)) {
        errno = EOPNOTSUPP;
        return -1;
    }
    resized = realloc(inventory->entries,
        (inventory->count + 1) * sizeof(*inventory->entries));
    if (resized == NULL) return -1;
    inventory->entries = resized;
    inventory->entries[inventory->count].path = strdup(path);
    if (inventory->entries[inventory->count].path == NULL) return -1;
    inventory->entries[inventory->count].status = *status;
    inventory->entries[inventory->count].digest[0] = '\0';
    if (digest != NULL)
        memcpy(inventory->entries[inventory->count].digest, digest, 65);
    inventory->entries[inventory->count].link_target =
        link_target == NULL ? NULL : strdup(link_target);
    if (link_target != NULL &&
        inventory->entries[inventory->count].link_target == NULL) {
        free(inventory->entries[inventory->count].path);
        return -1;
    }
    inventory->count++;
    return 0;
}

static int hash_open_file(int descriptor, const struct stat *expected,
                          char output[65])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char buffer[32768], digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    struct stat before, after;
    unsigned int length = 0;
    size_t index;
    int result = -1;
    if (context == NULL) { errno = ENOMEM; return -1; }
    if (fstat(descriptor, &before) < 0) goto done;
    if (!S_ISREG(before.st_mode) ||
        (expected != NULL && !same_version(expected, &before))) {
        errno = EBUSY; goto done;
    }
    if (lseek(descriptor, 0, SEEK_SET) < 0) goto done;
    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        errno = EIO; goto done;
    }
    for (;;) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (count == 0) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) {
            errno = EIO; goto done;
        }
    }
    if (fstat(descriptor, &after) < 0) goto done;
    if (!same_version(&before, &after)) { errno = EBUSY; goto done; }
    if (EVP_DigestFinal_ex(context, digest, &length) != 1 || length != 32) {
        errno = EIO; goto done;
    }
    for (index = 0; index < 32; index++) {
        output[index * 2] = hex[digest[index] >> 4];
        output[index * 2 + 1] = hex[digest[index] & 15];
    }
    output[64] = '\0';
    result = 0;
done:
    EVP_MD_CTX_free(context);
    return result;
}

static int compare_names(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

static int read_names(int directory_fd, char ***names_out, size_t *count_out)
{
    DIR *directory;
    struct dirent *entry;
    char **names = NULL;
    size_t count = 0;
    int copy = openat(directory_fd, ".",
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (copy < 0) return -1;
    directory = fdopendir(copy);
    if (directory == NULL) { close(copy); return -1; }
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) goto fail;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        if (count >= SNAPSHOT_ENTRY_LIMIT) { errno = E2BIG; goto fail; }
        {
            char **resized = realloc(names, (count + 1) * sizeof(*names));
            if (resized == NULL) goto fail;
            names = resized;
            names[count] = strdup(entry->d_name);
            if (names[count] == NULL) goto fail;
            count++;
        }
    }
    if (closedir(directory) < 0) goto names_fail;
    qsort(names, count, sizeof(*names), compare_names);
    *names_out = names;
    *count_out = count;
    return 0;
fail:
    {
        int saved = errno;
        closedir(directory);
        errno = saved;
    }
names_fail:
    while (count > 0) free(names[--count]);
    free(names);
    return -1;
}

static void free_names(char **names, size_t count)
{
    while (count > 0) free(names[--count]);
    free(names);
}

static int append_path(const char *parent, const char *name, char **path)
{
    size_t parent_length = strlen(parent), name_length = strlen(name);
    size_t separator = parent_length == 0 ? 0 : 1;
    if (parent_length > SNAPSHOT_PATH_LIMIT - name_length - separator) {
        errno = ENAMETOOLONG;
        return -1;
    }
    *path = malloc(parent_length + separator + name_length + 1);
    if (*path == NULL) return -1;
    if (separator != 0)
        (void)snprintf(*path, parent_length + separator + name_length + 1,
                       "%s/%s", parent, name);
    else
        (void)snprintf(*path, name_length + 1, "%s", name);
    return 0;
}

static int inventory_directory(int directory_fd, const char *prefix,
                               unsigned int depth,
                               struct inventory *inventory)
{
    struct stat before, after;
    char **names = NULL;
    size_t count = 0, index;
    if (depth > SNAPSHOT_DEPTH_LIMIT) { errno = ELOOP; return -1; }
    if (fstat(directory_fd, &before) < 0) return -1;
    if (!S_ISDIR(before.st_mode)) { errno = ENOTDIR; return -1; }
    if (inventory_add(inventory, prefix, &before, NULL, NULL) < 0 ||
        read_names(directory_fd, &names, &count) < 0) return -1;
    for (index = 0; index < count; index++) {
        char *path = NULL;
        struct stat status;
        int child;
        if (append_path(prefix, names[index], &path) < 0) goto fail;
        if (fstatat(directory_fd, names[index], &status,
                    AT_SYMLINK_NOFOLLOW) < 0) { free(path); goto fail; }
        if (!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode) &&
            !S_ISLNK(status.st_mode)) {
            free(path); errno = EOPNOTSUPP; goto fail;
        }
        if (S_ISDIR(status.st_mode)) {
            child = openat(directory_fd, names[index],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0) { free(path); goto fail; }
            if (inventory_directory(child, path, depth + 1, inventory) < 0) {
                int saved = errno;
                close(child); free(path); errno = saved; goto fail;
            }
            close(child);
        } else if (S_ISREG(status.st_mode)) {
            char digest[65];
            int file = openat(directory_fd, names[index],
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (file < 0) { free(path); goto fail; }
            if (hash_open_file(file, &status, digest) < 0) {
                int saved = errno; close(file); free(path); errno = saved;
                goto fail;
            }
            close(file);
            if (inventory_add(inventory, path, &status, digest, NULL) < 0) {
                free(path); goto fail;
            }
        } else {
            char target[SNAPSHOT_PATH_LIMIT + 1];
            ssize_t length = readlinkat(directory_fd, names[index], target,
                                        SNAPSHOT_PATH_LIMIT);
            struct stat after;
            if (length < 0) { free(path); goto fail; }
            if ((size_t)length >= SNAPSHOT_PATH_LIMIT) {
                free(path); errno = ENAMETOOLONG; goto fail;
            }
            target[length] = '\0';
            if (fstatat(directory_fd, names[index], &after,
                        AT_SYMLINK_NOFOLLOW) < 0) { free(path); goto fail; }
            if (!same_version(&status, &after)) {
                free(path); errno = EBUSY; goto fail;
            }
            if (inventory_add(inventory, path, &status, NULL, target) < 0) {
                free(path); goto fail;
            }
        }
        free(path);
    }
    free_names(names, count);
    if (fstat(directory_fd, &after) < 0) return -1;
    if (!same_version(&before, &after)) { errno = EBUSY; return -1; }
    return 0;
fail:
    free_names(names, count);
    return -1;
}

static int inventory_root(int root_fd, struct inventory *inventory)
{
    struct stat status;
    int result;
    memset(inventory, 0, sizeof(*inventory));
    if (fstat(root_fd, &status) < 0) return -1;
    if (S_ISDIR(status.st_mode)) {
        result = inventory_directory(root_fd, "", 0, inventory);
    } else if (S_ISREG(status.st_mode)) {
        char digest[65];
        if (hash_open_file(root_fd, &status, digest) < 0) result = -1;
        else result = inventory_add(inventory, "", &status, digest, NULL);
    } else {
        errno = EOPNOTSUPP;
        result = -1;
    }
    if (result < 0) inventory_clear(inventory);
    return result;
}

static int inventories_match(const struct inventory *left,
                             const struct inventory *right)
{
    size_t index;
    if (left->count != right->count) return 0;
    for (index = 0; index < left->count; index++)
        if (strcmp(left->entries[index].path, right->entries[index].path) != 0 ||
            !same_version(&left->entries[index].status,
                          &right->entries[index].status) ||
            strcmp(left->entries[index].digest,
                   right->entries[index].digest) != 0 ||
            ((left->entries[index].link_target == NULL) !=
             (right->entries[index].link_target == NULL)) ||
            (left->entries[index].link_target != NULL &&
             strcmp(left->entries[index].link_target,
                    right->entries[index].link_target) != 0)) return 0;
    return 1;
}

static int inventories_content_match(const struct inventory *source,
                                    const struct inventory *copy)
{
    size_t index;
    if (source->count != copy->count) return 0;
    for (index = 0; index < source->count; index++) {
        const struct stat *source_status = &source->entries[index].status;
        const struct stat *copy_status = &copy->entries[index].status;
        if (strcmp(source->entries[index].path,
                   copy->entries[index].path) != 0 ||
            (source_status->st_mode & (S_IFMT | 07777)) !=
                (copy_status->st_mode & (S_IFMT | 07777)) ||
            strcmp(source->entries[index].digest,
                   copy->entries[index].digest) != 0 ||
            ((source->entries[index].link_target == NULL) !=
             (copy->entries[index].link_target == NULL)) ||
            (source->entries[index].link_target != NULL &&
             strcmp(source->entries[index].link_target,
                    copy->entries[index].link_target) != 0)) return 0;
    }
    return 1;
}

static int open_source_root(int repository_fd, const char *path)
{
    char *copy = strdup(path), *part;
    int current = fcntl(repository_fd, F_DUPFD_CLOEXEC, 3);
    if (copy == NULL || current < 0) {
        int saved = errno;
        free(copy);
        if (current >= 0) close(current);
        errno = saved;
        return -1;
    }
    part = copy;
    while (part != NULL) {
        char *slash = strchr(part, '/');
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        struct stat status;
        int next;
        if (slash != NULL) { *slash = '\0'; flags |= O_DIRECTORY; }
        next = openat(current, part, flags);
        if (next < 0) goto fail;
        if (fstat(next, &status) < 0) {
            int saved = errno; close(next); errno = saved; goto fail;
        }
        if ((!S_ISDIR(status.st_mode) && !S_ISREG(status.st_mode)) ||
            (slash != NULL && !S_ISDIR(status.st_mode))) {
            close(next); errno = EOPNOTSUPP; goto fail;
        }
        close(current);
        current = next;
        part = slash == NULL ? NULL : slash + 1;
    }
    free(copy);
    return current;
fail:
    {
        int saved = errno;
        close(current); free(copy); errno = saved;
    }
    return -1;
}

static int copy_file(int source_fd, int destination_fd,
                     const struct stat *source_status,
                     struct copy_budget *budget)
{
    unsigned char buffer[32768];
    for (;;) {
        ssize_t count = read(source_fd, buffer, sizeof(buffer));
        size_t written = 0;
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) return -1;
        if (count == 0) break;
        if ((uint64_t)count > SNAPSHOT_BYTE_LIMIT - budget->bytes) {
            errno = EFBIG;
            return -1;
        }
        while (written < (size_t)count) {
            ssize_t result = write(destination_fd, buffer + written,
                                   (size_t)count - written);
            if (result < 0 && errno == EINTR) continue;
            if (result <= 0) return -1;
            written += (size_t)result;
        }
        budget->bytes += (uint64_t)count;
    }
    if (fchmod(destination_fd, source_status->st_mode & 07777) < 0)
        return -1;
    {
        struct timespec times[2] = {source_status->st_atim,
                                    source_status->st_mtim};
        return futimens(destination_fd, times);
    }
}

static int copy_entry(int source_directory, const char *name,
                      int destination_directory, unsigned int depth,
                      struct copy_budget *budget,
                      struct tm_snapshot *snapshot);

static int copy_directory(int source_fd, int destination_fd,
                          unsigned int depth, struct copy_budget *budget,
                          struct tm_snapshot *snapshot)
{
    char **names = NULL;
    size_t count = 0, index;
    struct stat before, after;
    if (depth > SNAPSHOT_DEPTH_LIMIT) { errno = ELOOP; return -1; }
    if (fstat(source_fd, &before) < 0) return -1;
    if (!S_ISDIR(before.st_mode)) { errno = ENOTDIR; return -1; }
    if (read_names(source_fd, &names, &count) < 0) return -1;
    for (index = 0; index < count; index++)
        if (copy_entry(source_fd, names[index], destination_fd,
                       depth + 1, budget, snapshot) < 0) {
            int saved = errno; free_names(names, count); errno = saved;
            return -1;
        }
    free_names(names, count);
    if (fstat(source_fd, &after) < 0) return -1;
    if (!same_version(&before, &after)) { errno = EBUSY; return -1; }
    if (fchmod(destination_fd, before.st_mode & 07777) < 0) return -1;
    {
        struct timespec times[2] = {before.st_atim, before.st_mtim};
        return futimens(destination_fd, times);
    }
}

static int copy_entry(int source_directory, const char *name,
                      int destination_directory, unsigned int depth,
                      struct copy_budget *budget,
                      struct tm_snapshot *snapshot)
{
    struct stat before, after;
    int source = -1, destination = -1, result = -1;
    char link_target[SNAPSHOT_PATH_LIMIT + 1];
    ssize_t link_length;
    if (fstatat(source_directory, name, &before,
                AT_SYMLINK_NOFOLLOW) < 0) return -1;
    if (S_ISDIR(before.st_mode)) {
        if (mkdirat(destination_directory, name, 0700) < 0) return -1;
        source = openat(source_directory, name,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        destination = openat(destination_directory, name,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (source < 0 || destination < 0) goto done;
        if (retain_directory(snapshot, destination) < 0 ||
            copy_directory(source, destination, depth, budget, snapshot) < 0)
            goto done;
    } else if (S_ISREG(before.st_mode)) {
        source = openat(source_directory, name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        if (source < 0) goto done;
        if (fstat(source, &after) < 0 || !same_version(&before, &after)) {
            errno = EBUSY; goto done;
        }
        destination = openat(destination_directory, name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (destination < 0 || copy_file(source, destination,
                                         &before, budget) < 0)
            goto done;
        if (fstat(source, &after) < 0) goto done;
        if (!same_version(&before, &after)) { errno = EBUSY; goto done; }
    } else if (S_ISLNK(before.st_mode)) {
        link_length = readlinkat(source_directory, name, link_target,
                                 sizeof(link_target) - 1);
        if (link_length < 0) return -1;
        if ((size_t)link_length >= sizeof(link_target) - 1) {
            errno = ENAMETOOLONG; return -1;
        }
        link_target[link_length] = '\0';
        if (symlinkat(link_target, destination_directory, name) < 0)
            return -1;
        {
            struct timespec times[2] = {before.st_atim, before.st_mtim};
            if (utimensat(destination_directory, name, times,
                          AT_SYMLINK_NOFOLLOW) < 0) return -1;
        }
        if (fstatat(source_directory, name, &after,
                    AT_SYMLINK_NOFOLLOW) < 0) return -1;
        if (!same_version(&before, &after)) { errno = EBUSY; return -1; }
    } else {
        errno = EOPNOTSUPP;
        return -1;
    }
    if (fstatat(source_directory, name, &after, AT_SYMLINK_NOFOLLOW) < 0)
        goto done;
    if (!same_version(&before, &after)) { errno = EBUSY; goto done; }
    result = 0;
done:
    {
        int saved = errno;
        if (source >= 0) close(source);
        if (destination >= 0) close(destination);
        errno = saved;
    }
    return result;
}

static int copy_root(int source_fd, int destination_directory,
                     const char *name, struct copy_budget *budget,
                     struct tm_snapshot *snapshot)
{
    struct stat status;
    int destination = -1, result = -1;
    if (fstat(source_fd, &status) < 0) return -1;
    if (S_ISDIR(status.st_mode)) {
        if (mkdirat(destination_directory, name, 0700) < 0) return -1;
        destination = openat(destination_directory, name,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (destination < 0) return -1;
        if (retain_directory(snapshot, destination) < 0) result = -1;
        else result = copy_directory(source_fd, destination, 0, budget,
                                     snapshot);
    } else if (S_ISREG(status.st_mode)) {
        destination = openat(destination_directory, name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (destination < 0) return -1;
        if (lseek(source_fd, 0, SEEK_SET) < 0) {
            int saved = errno;
            close(destination);
            errno = saved;
            return -1;
        }
        result = copy_file(source_fd, destination, &status, budget);
        if (result == 0) {
            struct stat after;
            if (fstat(source_fd, &after) < 0) result = -1;
            else if (!same_version(&status, &after)) {
                errno = EBUSY; result = -1;
            }
        }
    } else {
        errno = EOPNOTSUPP;
    }
    {
        int saved = errno;
        if (destination >= 0) close(destination);
        errno = saved;
    }
    return result;
}

static int remove_tree(int directory_fd)
{
    char **names = NULL;
    size_t count = 0, index;
    if (read_names(directory_fd, &names, &count) < 0) return -1;
    for (index = 0; index < count; index++) {
        struct stat status;
        if (fstatat(directory_fd, names[index], &status,
                    AT_SYMLINK_NOFOLLOW) < 0) goto fail;
        if (S_ISDIR(status.st_mode)) {
            int child = openat(directory_fd, names[index],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0) goto fail;
            if (remove_tree(child) < 0) {
                int saved = errno; close(child); errno = saved; goto fail;
            }
            close(child);
            if (unlinkat(directory_fd, names[index], AT_REMOVEDIR) < 0)
                goto fail;
        } else if (unlinkat(directory_fd, names[index], 0) < 0) {
            goto fail;
        }
    }
    free_names(names, count);
    return 0;
fail:
    {
        int saved = errno; free_names(names, count); errno = saved;
    }
    return -1;
}

int tm_snapshot_create(int repository_fd, const char *const *paths,
                       size_t path_count, struct tm_snapshot **output)
{
    struct tm_snapshot *snapshot = NULL;
    struct copy_budget budget = {0};
    size_t index;
    int result = -1;
    if (repository_fd < 0 || paths == NULL || path_count == 0 ||
        output == NULL || path_count > 10000) { errno = EINVAL; return -1; }
    *output = NULL;
    snapshot = calloc(1, sizeof(*snapshot));
    if (snapshot == NULL) return -1;
    snapshot->directory_fd = -1;
    snapshot->path = strdup("/tmp/tm-snapshot-XXXXXX");
    if (snapshot->path == NULL || mkdtemp(snapshot->path) == NULL) goto done;
    snapshot->directory_fd = open(snapshot->path,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (snapshot->directory_fd < 0) goto done;
    snapshot->root_count = path_count;
    for (index = 0; index < path_count; index++) {
        struct inventory before = {0}, after = {0}, copied = {0};
        char root_name[32];
        struct stat root_status;
        int source = open_source_root(repository_fd, paths[index]);
        int copied_fd = -1;
        int saved = 0;
        if (source < 0) goto done;
        if (inventory_root(source, &before) < 0) saved = errno;
        if (saved == 0 &&
            snprintf(root_name, sizeof(root_name), "root-%zu", index) < 0)
            saved = EOVERFLOW;
        if (saved == 0 && copy_root(source, snapshot->directory_fd, root_name,
                                    &budget, snapshot) < 0) saved = errno;
        if (saved == 0 && inventory_root(source, &after) < 0) saved = errno;
        if (saved == 0 && !inventories_match(&before, &after)) saved = EBUSY;
        if (saved == 0) {
            if (fstatat(snapshot->directory_fd, root_name, &root_status,
                        AT_SYMLINK_NOFOLLOW) < 0) saved = errno;
            else {
                int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
                if (S_ISDIR(root_status.st_mode)) flags |= O_DIRECTORY;
                copied_fd = openat(snapshot->directory_fd, root_name, flags);
                if (copied_fd < 0) saved = errno;
            }
        }
        if (saved == 0 && inventory_root(copied_fd, &copied) < 0)
            saved = errno;
        if (saved == 0 && !inventories_content_match(&before, &copied))
            saved = EIO;
        inventory_clear(&before); inventory_clear(&after);
        inventory_clear(&copied);
        if (copied_fd >= 0) close(copied_fd);
        close(source);
        if (saved != 0) { errno = saved; goto done; }
    }
    *output = snapshot;
    return 0;
done:
    {
        int saved = errno;
        tm_snapshot_free(snapshot);
        errno = saved;
    }
    return result;
}

int tm_snapshot_open_root(const struct tm_snapshot *snapshot, size_t index)
{
    char name[32];
    int descriptor;
    if (snapshot == NULL || snapshot->directory_fd < 0 ||
        index >= snapshot->root_count ||
        snprintf(name, sizeof(name), "root-%zu", index) < 0) {
        errno = EINVAL;
        return -1;
    }
    descriptor = openat(snapshot->directory_fd, name,
        O_PATH | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    return descriptor;
}

int tm_snapshot_open_root_readable(const struct tm_snapshot *snapshot,
                                   size_t index)
{
    char name[32];
    struct stat status;
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (snapshot == NULL || snapshot->directory_fd < 0 ||
        index >= snapshot->root_count ||
        snprintf(name, sizeof(name), "root-%zu", index) < 0) {
        errno = EINVAL;
        return -1;
    }
    if (fstatat(snapshot->directory_fd, name, &status,
                AT_SYMLINK_NOFOLLOW) < 0) return -1;
    if (S_ISDIR(status.st_mode)) flags |= O_DIRECTORY;
    else if (!S_ISREG(status.st_mode)) { errno = EOPNOTSUPP; return -1; }
    return openat(snapshot->directory_fd, name, flags);
}

void tm_snapshot_free(struct tm_snapshot *snapshot)
{
    size_t index;
    if (snapshot == NULL) return;
    if (snapshot->directory_fd >= 0) {
        for (index = 0; index < snapshot->directory_fd_count; index++) {
            (void)fchmod(snapshot->directory_fds[index], 0700);
            close(snapshot->directory_fds[index]);
        }
        (void)remove_tree(snapshot->directory_fd);
        close(snapshot->directory_fd);
        if (snapshot->path != NULL) (void)rmdir(snapshot->path);
    } else if (snapshot->path != NULL) {
        (void)rmdir(snapshot->path);
    }
    free(snapshot->directory_fds);
    free(snapshot->path);
    free(snapshot);
}
