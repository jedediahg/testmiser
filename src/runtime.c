#define _XOPEN_SOURCE 700
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

#include "tm/digest.h"
#include "tm/runtime.h"

#define RUNTIME_PATH_LIMIT 4096U
#define RUNTIME_ENTRY_LIMIT 1000000U
#define RUNTIME_LINK_LIMIT 4096U
#define RUNTIME_DEPTH_LIMIT 128U

struct runtime_tree {
    EVP_MD_CTX *digest;
    uint64_t entries;
};

struct runtime_names {
    char **items;
    size_t count;
    size_t capacity;
};

static int update(EVP_MD_CTX *digest, const void *data, size_t length)
{
    if (EVP_DigestUpdate(digest, data, length) != 1) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int update_u32(EVP_MD_CTX *digest, uint32_t value)
{
    unsigned char bytes[4] = {
        (unsigned char)(value >> 24), (unsigned char)(value >> 16),
        (unsigned char)(value >> 8), (unsigned char)value
    };
    return update(digest, bytes, sizeof(bytes));
}

static int update_u64(EVP_MD_CTX *digest, uint64_t value)
{
    unsigned char bytes[8];
    size_t index;
    for (index = 0; index < sizeof(bytes); index++)
        bytes[index] = (unsigned char)(value >> (56 - index * 8));
    return update(digest, bytes, sizeof(bytes));
}

static int same_version(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_size == right->st_size &&
           left->st_nlink == right->st_nlink &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int compare_names(const void *left, const void *right)
{
    const char *const *a = left;
    const char *const *b = right;
    return strcmp(*a, *b);
}

static void clear_names(struct runtime_names *names)
{
    size_t index;
    for (index = 0; index < names->count; index++) free(names->items[index]);
    free(names->items);
    memset(names, 0, sizeof(*names));
}

static int add_name(struct runtime_names *names, const char *name)
{
    char **grown;
    size_t capacity;
    if (names->count == names->capacity) {
        capacity = names->capacity == 0 ? 64 : names->capacity * 2;
        if (capacity < names->capacity ||
            capacity > RUNTIME_ENTRY_LIMIT) capacity = RUNTIME_ENTRY_LIMIT;
        if (capacity == names->capacity) { errno = E2BIG; return -1; }
        grown = realloc(names->items, capacity * sizeof(*names->items));
        if (grown == NULL) return -1;
        names->items = grown;
        names->capacity = capacity;
    }
    names->items[names->count] = strdup(name);
    if (names->items[names->count] == NULL) return -1;
    names->count++;
    return 0;
}

static int read_file_digest(int parent, const char *name,
                            const struct stat *expected,
                            unsigned char digest[32])
{
    unsigned char buffer[32768];
    EVP_MD_CTX *context = NULL;
    struct stat before, after;
    unsigned int digest_length = 0;
    int descriptor = openat(parent, name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int result = -1, saved;
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &before) < 0 || !S_ISREG(before.st_mode) ||
        !same_version(expected, &before)) { errno = EBUSY; goto done; }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        errno = EIO;
        goto done;
    }
    for (;;) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (count == 0) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) {
            errno = EIO;
            goto done;
        }
    }
    if (fstat(descriptor, &after) < 0 || !same_version(&before, &after) ||
        EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length != 32) { errno = EBUSY; goto done; }
    result = 0;
done:
    saved = errno;
    EVP_MD_CTX_free(context);
    close(descriptor);
    errno = saved;
    return result;
}

static int add_record(struct runtime_tree *tree, unsigned char type,
                      const char *path, const struct stat *status,
                      int parent, const char *name)
{
    size_t path_length = strlen(path);
    uint32_t mode = (uint32_t)(status->st_mode & 07777);
    unsigned char content_digest[32];
    int result;
    if (path_length > RUNTIME_PATH_LIMIT || path_length > UINT32_MAX ||
        status->st_nlink < 1 || tree->entries == RUNTIME_ENTRY_LIMIT) {
        errno = E2BIG;
        return -1;
    }
    if (update(tree->digest, &type, 1) < 0 ||
        update_u32(tree->digest, (uint32_t)path_length) < 0 ||
        update(tree->digest, path, path_length) < 0 ||
        update_u32(tree->digest, mode) < 0 ||
        update_u32(tree->digest, (uint32_t)status->st_uid) < 0 ||
        update_u32(tree->digest, (uint32_t)status->st_gid) < 0 ||
        update_u64(tree->digest, (uint64_t)status->st_nlink) < 0) return -1;
    tree->entries++;
    if (type == 'f') {
        if (status->st_size < 0 ||
            read_file_digest(parent, name, status, content_digest) < 0)
            return -1;
        if (update_u64(tree->digest, (uint64_t)status->st_size) < 0 ||
            update(tree->digest, content_digest, sizeof(content_digest)) < 0)
            return -1;
    } else if (type == 'l') {
        char target[RUNTIME_LINK_LIMIT + 1];
        ssize_t length = readlinkat(parent, name, target, RUNTIME_LINK_LIMIT);
        struct stat after;
        if (length < 0) return -1;
        if (length == RUNTIME_LINK_LIMIT ||
            fstatat(parent, name, &after, AT_SYMLINK_NOFOLLOW) < 0 ||
            !same_version(status, &after)) { errno = EBUSY; return -1; }
        if ((uint64_t)length > UINT32_MAX ||
            update_u32(tree->digest, (uint32_t)length) < 0) return -1;
        result = update(tree->digest, target, (size_t)length);
        if (result < 0) return -1;
    }
    return 0;
}

static int hash_directory(struct runtime_tree *tree, int directory,
                          const char *prefix, const struct stat *expected,
                          unsigned int depth)
{
    struct runtime_names names = {0};
    struct stat before, after;
    DIR *stream = NULL;
    int scan = -1, result = -1, saved;
    size_t index;

    if (depth > RUNTIME_DEPTH_LIMIT) { errno = E2BIG; return -1; }
    if (fstat(directory, &before) < 0 || !S_ISDIR(before.st_mode) ||
        (expected != NULL && !same_version(expected, &before))) {
        errno = EBUSY;
        return -1;
    }
    scan = dup(directory);
    if (scan < 0) goto done;
    stream = fdopendir(scan);
    if (stream == NULL) goto done;
    scan = -1;
    for (;;) {
        struct dirent *entry;
        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) goto done;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) continue;
        if (names.count == RUNTIME_ENTRY_LIMIT ||
            add_name(&names, entry->d_name) < 0) goto done;
    }
    if (fstat(directory, &after) < 0 || !same_version(&before, &after)) {
        errno = EBUSY;
        goto done;
    }
    if (names.count > 1)
        qsort(names.items, names.count, sizeof(*names.items), compare_names);
    for (index = 0; index < names.count; index++) {
        struct stat child_status;
        char *child_path;
        size_t prefix_length = strlen(prefix), name_length = strlen(names.items[index]);
        int amount;
        if (name_length > RUNTIME_PATH_LIMIT - 2 ||
            prefix_length > RUNTIME_PATH_LIMIT - name_length - 2) {
            errno = ENAMETOOLONG;
            goto done;
        }
        child_path = malloc(prefix_length + name_length + 2);
        if (child_path == NULL) goto done;
        amount = prefix_length == 0 ?
            snprintf(child_path, prefix_length + name_length + 2, "%s",
                     names.items[index]) :
            snprintf(child_path, prefix_length + name_length + 2, "%s/%s",
                     prefix, names.items[index]);
        if (amount < 0 || (size_t)amount > RUNTIME_PATH_LIMIT ||
            fstatat(directory, names.items[index], &child_status,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            free(child_path);
            if (errno == 0) errno = EIO;
            goto done;
        }
        if (S_ISREG(child_status.st_mode)) {
            if (add_record(tree, 'f', child_path, &child_status, directory,
                           names.items[index]) < 0) {
                free(child_path);
                goto done;
            }
        } else if (S_ISDIR(child_status.st_mode)) {
            int child = openat(directory, names.items[index],
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0 || add_record(tree, 'd', child_path,
                    &child_status, -1, NULL) < 0 ||
                hash_directory(tree, child, child_path, &child_status,
                               depth + 1) < 0) {
                int child_error = errno;
                if (child >= 0) close(child);
                free(child_path);
                errno = child_error;
                goto done;
            }
            close(child);
        } else if (S_ISLNK(child_status.st_mode)) {
            if (add_record(tree, 'l', child_path, &child_status, directory,
                           names.items[index]) < 0) {
                free(child_path);
                goto done;
            }
        } else {
            free(child_path);
            errno = EOPNOTSUPP;
            goto done;
        }
        free(child_path);
    }
    if (fstat(directory, &after) < 0 || !same_version(&before, &after)) {
        errno = EBUSY;
        goto done;
    }
    result = 0;
done:
    saved = errno;
    if (stream != NULL) closedir(stream);
    if (scan >= 0) close(scan);
    clear_names(&names);
    errno = saved;
    return result;
}

int tm_runtime_tree_digest(const char *root, char output[72])
{
    static const unsigned char domain[] = "tm-runtime-tree-v1\0";
    char *canonical = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    struct runtime_tree tree = {0};
    struct stat status;
    int directory = -1, result = -1, saved;

    if (root == NULL || output == NULL) { errno = EINVAL; return -1; }
    canonical = realpath(root, NULL);
    if (canonical == NULL) return -1;
    directory = open(canonical,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0 || fstat(directory, &status) < 0) goto done;
    tree.digest = EVP_MD_CTX_new();
    if (tree.digest == NULL ||
        EVP_DigestInit_ex(tree.digest, EVP_sha256(), NULL) != 1 ||
        update(tree.digest, domain, sizeof(domain) - 1) < 0 ||
        add_record(&tree, 'd', "", &status, -1, NULL) < 0 ||
        hash_directory(&tree, directory, "", &status, 0) < 0 ||
        EVP_DigestFinal_ex(tree.digest, digest, &digest_length) != 1 ||
        digest_length != 32) {
        if (errno == 0) errno = EIO;
        goto done;
    }
    {
        static const char digits[] = "0123456789abcdef";
        size_t index;
        memcpy(output, "sha256:", 7);
        for (index = 0; index < 32; index++) {
            output[7 + index * 2] = digits[digest[index] >> 4];
            output[8 + index * 2] = digits[digest[index] & 0x0f];
        }
        output[71] = '\0';
    }
    result = 0;
done:
    saved = errno;
    EVP_MD_CTX_free(tree.digest);
    if (directory >= 0) close(directory);
    free(canonical);
    errno = saved;
    return result;
}
