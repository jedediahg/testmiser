#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/digest.h"
#include "tm/input.h"
#include "tm/json.h"

#define INPUT_PATH_LIMIT 4096U
#define DIRECTORY_ENTRY_LIMIT 100000U

struct directory_entry {
    char *name;
    const char *type;
};

static int valid_utf8(const unsigned char *s)
{
    while (*s != 0) {
        unsigned int first = *s++, count, minimum, codepoint, i;
        if (first < 0x80) continue;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1; minimum = 0x80; codepoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2; minimum = 0x800; codepoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3; minimum = 0x10000; codepoint = first & 0x07;
        } else return 0;
        for (i = 0; i < count; i++) {
            unsigned int next = *s++;
            if (next == 0 || (next & 0xc0) != 0x80) return 0;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) return 0;
    }
    return 1;
}

static int valid_relative_path(const char *path)
{
    const char *part, *cursor;
    if (path == NULL || path[0] == '\0' || path[0] == '/' ||
        strlen(path) > INPUT_PATH_LIMIT ||
        !valid_utf8((const unsigned char *)path)) return 0;
    part = path;
    for (cursor = path;; cursor++) {
        if (*cursor == '/' || *cursor == '\0') {
            size_t n = (size_t)(cursor - part);
            if (n == 0 || (n == 1 && part[0] == '.') ||
                (n == 2 && part[0] == '.' && part[1] == '.')) return 0;
            if (*cursor == '\0') return 1;
            part = cursor + 1;
        }
    }
}

static int valid_symlink_target(const char *target)
{
    const char *part;
    if (target == NULL || target[0] == '\0' || target[0] == '/' ||
        !valid_utf8((const unsigned char *)target)) return 0;
    for (part = target; *part != '\0';) {
        const char *end = strchr(part, '/');
        size_t length = end == NULL ? strlen(part) : (size_t)(end - part);
        if (length == 2 && part[0] == '.' && part[1] == '.') return 0;
        if (end == NULL) break;
        part = end + 1;
    }
    return 1;
}

static int same_version(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_mode == b->st_mode && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
           a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int valid_digest(const char *digest)
{
    size_t i;
    if (digest == NULL || strlen(digest) != 71 ||
        memcmp(digest, "sha256:", 7) != 0) return 0;
    for (i = 7; i < 71; i++)
        if (!((digest[i] >= '0' && digest[i] <= '9') ||
              (digest[i] >= 'a' && digest[i] <= 'f'))) return 0;
    return 1;
}

static int open_parent(int root_fd, const char *path, char **leaf)
{
    char *copy = strdup(path);
    char *slash;
    int current = dup(root_fd);
    if (copy == NULL || current < 0) { free(copy); return -1; }
    slash = strrchr(copy, '/');
    if (slash != NULL) {
        char *part;
        *slash = '\0';
        part = copy;
        while (*part != '\0') {
            char *next = strchr(part, '/');
            int child;
            if (next != NULL) *next = '\0';
            child = openat(current, part,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child < 0) {
                int saved = errno;
                struct stat component_stat;
                if (fstatat(current, part, &component_stat,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISLNK(component_stat.st_mode)) saved = ELOOP;
                close(current); free(copy); errno = saved; return -1;
            }
            close(current);
            current = child;
            if (next == NULL) break;
            part = next + 1;
        }
        *slash = '/';
        *leaf = strdup(slash + 1);
    } else {
        *leaf = strdup(copy);
    }
    free(copy);
    if (*leaf == NULL) { close(current); return -1; }
    return current;
}

static int hash_file_at(int parent, const char *leaf, char hex[65])
{
    unsigned char data[32768], digest[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *ctx = NULL;
    struct stat before, after;
    unsigned int digest_length = 0;
    int fd = openat(parent, leaf,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int result = -1, saved;
    if (fd < 0) return -1;
    if (fstat(fd, &before) < 0) goto done;
    if (!S_ISREG(before.st_mode)) { errno = EINVAL; goto done; }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        errno = EIO; goto done;
    }
    for (;;) {
        ssize_t count = read(fd, data, sizeof(data));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto done;
        if (count == 0) break;
        if (EVP_DigestUpdate(ctx, data, (size_t)count) != 1) {
            errno = EIO; goto done;
        }
    }
    if (fstat(fd, &after) < 0) goto done;
    if (!same_version(&before, &after)) { errno = EBUSY; goto done; }
    if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
        digest_length != 32) { errno = EIO; goto done; }
    {
        static const char digits[] = "0123456789abcdef";
        size_t i;
        for (i = 0; i < 32; i++) {
            hex[i * 2] = digits[digest[i] >> 4];
            hex[i * 2 + 1] = digits[digest[i] & 15];
        }
        hex[64] = '\0';
    }
    result = 0;
done:
    saved = errno;
    EVP_MD_CTX_free(ctx);
    close(fd);
    errno = saved;
    return result;
}

int tm_input_capture_file(int root_fd, const char *path, char digest[72])
{
    char *leaf = NULL;
    char hex[65];
    int parent;
    int result = -1;
    int saved;

    if (root_fd < 0 || digest == NULL || !valid_relative_path(path)) {
        errno = EINVAL;
        return -1;
    }
    parent = open_parent(root_fd, path, &leaf);
    if (parent < 0) return -1;
    if (hash_file_at(parent, leaf, hex) < 0) goto done;
    memcpy(digest, "sha256:", 7);
    memcpy(digest + 7, hex, sizeof(hex));
    result = 0;
done:
    saved = errno;
    close(parent);
    free(leaf);
    errno = saved;
    return result;
}

static const char *entry_type(mode_t mode)
{
    if (S_ISREG(mode)) return "file";
    if (S_ISDIR(mode)) return "directory";
    if (S_ISLNK(mode)) return "symlink";
    return NULL;
}

static int compare_entries(const void *a, const void *b)
{
    const struct directory_entry *left = a, *right = b;
    return strcmp(left->name, right->name);
}

static void free_entries(struct directory_entry *entries, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++) free(entries[i].name);
    free(entries);
}

static int hash_directory_at(int parent, const char *leaf, char hex[65])
{
    struct directory_entry *entries = NULL;
    struct stat before, after;
    struct tm_json_value *array = NULL;
    unsigned char *canonical = NULL;
    size_t canonical_length = 0, count = 0;
    DIR *dir = NULL;
    int fd = -1, result = -1, saved;

    fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) goto done;
    if (fstat(fd, &before) < 0) goto done;
    dir = fdopendir(dup(fd));
    if (dir == NULL) goto done;
    entries = calloc(DIRECTORY_ENTRY_LIMIT, sizeof(*entries));
    if (entries == NULL) goto done;
    for (;;) {
        struct dirent *entry;
        struct stat child_stat;
        const char *type;
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL) {
            if (errno != 0) goto done;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (count == DIRECTORY_ENTRY_LIMIT) { errno = E2BIG; goto done; }
        if (!valid_utf8((const unsigned char *)entry->d_name) ||
            fstatat(fd, entry->d_name, &child_stat, AT_SYMLINK_NOFOLLOW) < 0 ||
            (type = entry_type(child_stat.st_mode)) == NULL) {
            errno = EOPNOTSUPP; goto done;
        }
        entries[count].name = strdup(entry->d_name);
        entries[count].type = type;
        if (entries[count].name == NULL) goto done;
        count++;
    }
    if (fstat(fd, &after) < 0 || !same_version(&before, &after)) {
        errno = EBUSY; goto done;
    }
    if (count > 1) qsort(entries, count, sizeof(*entries), compare_entries);
    array = tm_json_new_array();
    if (array == NULL) goto done;
    for (size_t i = 0; i < count; i++) {
        struct tm_json_value *pair = tm_json_new_array();
        struct tm_json_value *name = tm_json_new_string(entries[i].name);
        struct tm_json_value *type = tm_json_new_string(entries[i].type);
        if (pair == NULL || name == NULL || type == NULL) {
            tm_json_free(pair); tm_json_free(name); tm_json_free(type); goto done;
        }
        if (tm_json_array_append(pair, name) < 0) {
            tm_json_free(pair); tm_json_free(name); tm_json_free(type); goto done;
        }
        name = NULL;
        if (tm_json_array_append(pair, type) < 0) {
            tm_json_free(pair); tm_json_free(type); goto done;
        }
        type = NULL;
        if (tm_json_array_append(array, pair) < 0) {
            tm_json_free(pair); goto done;
        }
    }
    if (tm_json_canonicalize(array, &canonical, &canonical_length) < 0 ||
        tm_sha256_bytes(canonical, canonical_length, hex) < 0) goto done;
    result = 0;
done:
    saved = errno;
    if (dir != NULL) closedir(dir);
    if (fd >= 0) close(fd);
    tm_json_free(array);
    free(canonical);
    free_entries(entries, count);
    errno = saved;
    return result;
}

int tm_input_capture_directory(int root_fd, const char *path, char digest[72])
{
    char *leaf = NULL;
    char hex[65];
    int parent, result = -1, saved;
    if (root_fd < 0 || digest == NULL || !valid_relative_path(path)) {
        errno = EINVAL;
        return -1;
    }
    parent = open_parent(root_fd, path, &leaf);
    if (parent < 0) return -1;
    if (hash_directory_at(parent, leaf, hex) < 0) goto done;
    memcpy(digest, "sha256:", 7);
    memcpy(digest + 7, hex, sizeof(hex));
    result = 0;
done:
    saved = errno;
    close(parent);
    free(leaf);
    errno = saved;
    return result;
}

int tm_input_capture_exists(int root_fd, const char *path, int *exists)
{
    char *leaf = NULL;
    int parent;
    struct stat status;
    if (root_fd < 0 || exists == NULL || !valid_relative_path(path)) {
        errno = EINVAL;
        return -1;
    }
    parent = open_parent(root_fd, path, &leaf);
    if (parent < 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            *exists = 0;
            return 0;
        }
        return -1;
    }
    if (fstatat(parent, leaf, &status, AT_SYMLINK_NOFOLLOW) == 0) {
        *exists = 1;
    } else if (errno == ENOENT) {
        *exists = 0;
    } else {
        int saved = errno;
        close(parent);
        free(leaf);
        errno = saved;
        return -1;
    }
    close(parent);
    free(leaf);
    return 0;
}

int tm_input_capture_symlink(int root_fd, const char *path, char **target)
{
    char *leaf = NULL, *copy = NULL;
    char buffer[INPUT_PATH_LIMIT + 1];
    struct stat before, after;
    ssize_t length;
    int parent, saved;
    if (target == NULL) { errno = EINVAL; return -1; }
    *target = NULL;
    if (root_fd < 0 || !valid_relative_path(path)) {
        errno = EINVAL;
        return -1;
    }
    parent = open_parent(root_fd, path, &leaf);
    if (parent < 0) return -1;
    if (fstatat(parent, leaf, &before, AT_SYMLINK_NOFOLLOW) < 0) goto fail;
    if (!S_ISLNK(before.st_mode)) { errno = EINVAL; goto fail; }
    length = readlinkat(parent, leaf, buffer, sizeof(buffer) - 1);
    if (length < 0) goto fail;
    if ((size_t)length >= sizeof(buffer) - 1 ||
        fstatat(parent, leaf, &after, AT_SYMLINK_NOFOLLOW) < 0 ||
        !same_version(&before, &after)) {
        errno = EBUSY;
        goto fail;
    }
    buffer[length] = '\0';
    if (!valid_symlink_target(buffer)) { errno = EOPNOTSUPP; goto fail; }
    copy = strdup(buffer);
    if (copy == NULL) goto fail;
    *target = copy;
    close(parent);
    free(leaf);
    return 0;
fail:
    saved = errno;
    close(parent);
    free(leaf);
    free(copy);
    errno = saved;
    return -1;
}

static int check_one(int root_fd, const struct tm_input_observation *input)
{
    char *leaf = NULL;
    int parent;
    struct stat st;
    int result = -1;
    if (!valid_relative_path(input->path)) { errno = EINVAL; return -1; }
    parent = open_parent(root_fd, input->path, &leaf);
    if (parent < 0) {
        if (input->kind == TM_INPUT_EXISTS &&
            (errno == ENOENT || errno == ENOTDIR))
            return input->exists ? 1 : 0;
        if (errno == ENOENT || errno == ENOTDIR) return 1;
        return -1;
    }
    if (input->kind == TM_INPUT_EXISTS) {
        if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0)
            result = input->exists ? 0 : 1;
        else if (errno == ENOENT) result = input->exists ? 1 : 0;
        else result = -1;
    } else if (input->kind == TM_INPUT_FILE) {
        char digest[65];
        if (hash_file_at(parent, leaf, digest) == 0) {
            if (valid_digest(input->digest))
                result = strcmp(input->digest + 7, digest) == 0 ? 0 : 1;
            else { errno = EINVAL; result = -1; }
        } else if (errno == ENOENT) result = 1;
    } else if (input->kind == TM_INPUT_DIRECTORY) {
        char digest[65];
        if (hash_directory_at(parent, leaf, digest) == 0) {
            if (valid_digest(input->digest))
                result = strcmp(input->digest + 7, digest) == 0 ? 0 : 1;
            else { errno = EINVAL; result = -1; }
        } else if (errno == ENOENT || errno == ENOTDIR) result = 1;
    } else if (input->kind == TM_INPUT_SYMLINK) {
        char target[INPUT_PATH_LIMIT + 1];
        ssize_t n;
        if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno == ENOENT) result = 1;
        } else if (!S_ISLNK(st.st_mode)) result = 1;
        else {
            struct stat after;
            n = readlinkat(parent, leaf, target, sizeof(target) - 1);
            if (n < 0) goto cleanup;
            if ((size_t)n >= sizeof(target) - 1 ||
                fstatat(parent, leaf, &after, AT_SYMLINK_NOFOLLOW) < 0 ||
                !same_version(&st, &after)) { errno = EBUSY; goto cleanup; }
            target[n] = '\0';
            if (!valid_symlink_target(target)) {
                errno = EOPNOTSUPP; goto cleanup;
            }
            if (input->target == NULL) { errno = EINVAL; goto cleanup; }
            result = strcmp(input->target, target) == 0 ? 0 : 1;
        }
    } else {
        errno = EINVAL;
    }
cleanup:
    {
        int saved = errno;
        close(parent);
        free(leaf);
        errno = saved;
    }
    return result;
}

int tm_input_matches(int root_fd,
                     const struct tm_input_observation *observation)
{
    if (root_fd < 0 || observation == NULL) { errno = EINVAL; return -1; }
    return check_one(root_fd, observation);
}
