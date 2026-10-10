#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/fs.h>

#include "tm/outputs.h"

#define OUTPUT_PATH_LIMIT 4096U
#define OUTPUT_ENTRY_LIMIT 100000U
#define OUTPUT_ROOT_LIMIT 1024U

static atomic_ulong stage_sequence;
static int valid_relative_path(const char *path);
static int open_parent(int root_fd, const char *path, char **leaf);
static int verify_existing_blob(int blob_fd, const char *name,
                                const char *expected_digest, uint64_t size);

static int remove_tree_at(int parent, const char *name)
{
    struct stat st;
    if (fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) < 0) return -1;
    if (!S_ISDIR(st.st_mode)) return unlinkat(parent, name, 0);
    {
        int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int duplicate, result = -1;
        DIR *dir;
        if (fd < 0) return -1;
        duplicate = dup(fd);
        if (duplicate < 0) { close(fd); return -1; }
        dir = fdopendir(duplicate);
        if (dir == NULL) { close(duplicate); close(fd); return -1; }
        for (;;) {
            struct dirent *entry;
            errno = 0;
            entry = readdir(dir);
            if (entry == NULL) {
                if (errno != 0) goto done;
                break;
            }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            if (remove_tree_at(fd, entry->d_name) < 0) goto done;
        }
        result = 0;
done:
        closedir(dir);
        close(fd);
        if (result == 0) result = unlinkat(parent, name, AT_REMOVEDIR);
        return result;
    }
}

static int read_blob_directory(int root)
{
    int tmfd = openat(root, ".tm", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int blobs = -1, sha = -1, saved;
    if (tmfd < 0) return -1;
    blobs = openat(tmfd, "blobs", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (blobs >= 0) sha = openat(blobs, "sha256", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    saved = errno;
    close(tmfd);
    if (blobs >= 0) close(blobs);
    errno = saved;
    return sha;
}

static int restore_file(int blobfd, int parentfd, const char *leaf,
                        const struct tm_output_entry *entry)
{
    char name[65];
    unsigned char buffer[32768];
    unsigned char hash[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *digest_context = NULL;
    unsigned int hash_length = 0;
    size_t i;
    uint64_t copied = 0;
    int source = -1, destination = -1, result = -1, saved, destination_created = 0;
    for (i = 0; i < 32; i++) name[i * 2] = entry->digest[7 + i * 2];
    for (i = 0; i < 32; i++) name[i * 2 + 1] = entry->digest[8 + i * 2];
    name[64] = '\0';
    if (verify_existing_blob(blobfd, name, entry->digest, entry->size) < 0) return -1;
    source = openat(blobfd, name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source < 0) goto done;
    digest_context = EVP_MD_CTX_new();
    if (digest_context == NULL ||
        EVP_DigestInit_ex(digest_context, EVP_sha256(), NULL) != 1) {
        errno = EIO; goto done;
    }
    destination = openat(parentfd, leaf,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (destination < 0) goto done;
    destination_created = 1;
    for (;;) {
        ssize_t n = read(source, buffer, sizeof(buffer));
        size_t offset = 0;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (n == 0) break;
        if (EVP_DigestUpdate(digest_context, buffer, (size_t)n) != 1) {
            errno = EIO; goto done;
        }
        while (offset < (size_t)n) {
            ssize_t w = write(destination, buffer + offset, (size_t)n - offset);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { errno = EIO; goto done; }
            offset += (size_t)w;
        }
        copied += (uint64_t)n;
    }
    if (copied != entry->size ||
        EVP_DigestFinal_ex(digest_context, hash, &hash_length) != 1 ||
        hash_length != 32 ||
        fchmod(destination, entry->mode) < 0 ||
        fsync(destination) < 0) { if (copied != entry->size) errno = EIO; goto done; }
    {
        static const char hex[] = "0123456789abcdef";
        char actual[72];
        size_t j;
        memcpy(actual, "sha256:", 7);
        for (j = 0; j < 32; j++) {
            actual[7 + j * 2] = hex[hash[j] >> 4];
            actual[8 + j * 2] = hex[hash[j] & 15];
        }
        actual[71] = '\0';
        if (strcmp(actual, entry->digest) != 0) { errno = EIO; goto done; }
    }
    result = 0;
done:
    saved = errno;
    EVP_MD_CTX_free(digest_context);
    if (source >= 0) close(source);
    if (destination >= 0) close(destination);
    if (result < 0 && destination_created) unlinkat(parentfd, leaf, 0);
    errno = saved;
    return result;
}

static int root_contains(const char *root, const char *path)
{
    size_t n = strlen(root);
    return strncmp(root, path, n) == 0 && (path[n] == '\0' || path[n] == '/');
}

static int restore_staged_root(int rootfd, int blobfd, const char *root,
                               const struct tm_output_manifest *manifest)
{
    char *leaf = NULL, stage[80] = {0};
    const struct tm_output_entry *root_entry = NULL;
    int parent = -1, stagefd = -1, result = -1, saved, stage_created = 0;
    size_t i;
    unsigned long sequence = atomic_fetch_add(&stage_sequence, 1);
    for (i = 0; i < manifest->count; i++)
        if (strcmp(manifest->entries[i].path, root) == 0) root_entry = &manifest->entries[i];
    if (root_entry == NULL) { errno = EINVAL; goto done; }
    parent = open_parent(rootfd, root, &leaf);
    if (parent < 0) goto done;
    if (snprintf(stage, sizeof(stage), ".tm-restore-%ld-%lu", (long)getpid(), sequence) >= (int)sizeof(stage)) { errno = EOVERFLOW; goto done; }
    if (root_entry->kind == TM_OUTPUT_DIRECTORY) {
        if (mkdirat(parent, stage, 0700) < 0) goto done;
        stage_created = 1;
        stagefd = openat(parent, stage, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (stagefd < 0) goto done;
    }
    for (i = 0; i < manifest->count; i++) {
        const struct tm_output_entry *entry = &manifest->entries[i];
        const char *relative;
        char *target = NULL;
        int target_parent = -1;
        if (!root_contains(root, entry->path)) continue;
        relative = entry->path + strlen(root);
        if (*relative == '/') relative++;
        if (*relative == '\0') {
            continue;
        }
        target_parent = open_parent(stagefd, relative, &target);
        if (target_parent < 0) {
            /* Parent directories must have appeared earlier in sorted order. */
            goto done;
        }
        if (entry->kind == TM_OUTPUT_DIRECTORY) {
            if (mkdirat(target_parent, target, 0700) < 0) {
                close(target_parent); free(target); goto done;
            }
            if (fsync(target_parent) < 0) {
                close(target_parent); free(target); goto done;
            }
        } else if (restore_file(blobfd, target_parent, target, entry) < 0) {
            close(target_parent); free(target); goto done;
        } else if (fsync(target_parent) < 0) {
            close(target_parent); free(target); goto done;
        }
        close(target_parent);
        free(target);
    }
    /* Declared directory roots are the staging directory itself. */
    for (i = manifest->count; i > 0; i--) {
        const struct tm_output_entry *entry = &manifest->entries[i - 1];
        if (!root_contains(root, entry->path) || entry->kind != TM_OUTPUT_DIRECTORY ||
            strcmp(entry->path, root) == 0) continue;
        {
            char *dirleaf = NULL;
            int dirparent = open_parent(stagefd, entry->path + strlen(root) + 1, &dirleaf);
            if (dirparent < 0 || fchmodat(dirparent, dirleaf, entry->mode, 0) < 0) {
                if (dirparent >= 0) close(dirparent);
                free(dirleaf); goto done;
            }
            if (fsync(dirparent) < 0) {
                close(dirparent); free(dirleaf); goto done;
            }
            close(dirparent); free(dirleaf);
        }
    }
    if (root_entry->kind == TM_OUTPUT_DIRECTORY) {
        if (fchmod(stagefd, root_entry->mode) < 0 || fsync(stagefd) < 0) goto done;
        close(stagefd); stagefd = -1;
    } else {
        if (restore_file(blobfd, parent, stage, root_entry) < 0) goto done;
        stage_created = 1;
        if (fsync(parent) < 0) goto done;
    }
    {
        struct stat old;
        if (fstatat(parent, leaf, &old, AT_SYMLINK_NOFOLLOW) == 0) {
            if (syscall(SYS_renameat2, parent, stage, parent, leaf, RENAME_EXCHANGE) < 0) goto done;
            if (remove_tree_at(parent, stage) < 0) goto done;
        } else if (errno == ENOENT) {
            if (renameat(parent, stage, parent, leaf) < 0) goto done;
        } else goto done;
    }
    if (fsync(parent) < 0) goto done;
    result = 0;
done:
    saved = errno;
    if (stagefd >= 0) close(stagefd);
    if (parent >= 0 && stage_created) (void)remove_tree_at(parent, stage);
    if (parent >= 0) close(parent);
    free(leaf);
    errno = saved;
    return result;
}

static int valid_utf8(const unsigned char *text)
{
    while (*text != 0) {
        unsigned int first = *text++, count, minimum, codepoint, i;
        if (first < 0x80) continue;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1; minimum = 0x80; codepoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2; minimum = 0x800; codepoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3; minimum = 0x10000; codepoint = first & 0x07;
        } else return 0;
        for (i = 0; i < count; i++) {
            unsigned int next = *text++;
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
    size_t length;
    if (path == NULL || path[0] == '\0' || path[0] == '/' ||
        (length = strlen(path)) > OUTPUT_PATH_LIMIT ||
        (strncmp(path, ".tm", 3) == 0 &&
         (path[3] == '\0' || path[3] == '/')) ||
        (strncmp(path, ".git", 4) == 0 &&
         (path[4] == '\0' || path[4] == '/')) ||
        !valid_utf8((const unsigned char *)path))
        return 0;
    part = path;
    for (cursor = path;; cursor++) {
        if (*cursor == '/' || *cursor == '\0') {
            size_t component = (size_t)(cursor - part);
            if (component == 0 || (component == 1 && part[0] == '.') ||
                (component == 2 && part[0] == '.' && part[1] == '.'))
                return 0;
            if (*cursor == '\0') return 1;
            part = cursor + 1;
        }
    }
}

static int same_version(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
           left->st_size == right->st_size &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static int open_parent(int root_fd, const char *path, char **leaf)
{
    char *copy = strdup(path), *part;
    int current = dup(root_fd);
    if (copy == NULL || current < 0) { free(copy); return -1; }
    part = copy;
    for (;;) {
        char *slash = strchr(part, '/');
        if (slash == NULL) {
            *leaf = strdup(part);
            break;
        }
        *slash = '\0';
        {
            int next = openat(current, part,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (next < 0) {
                int saved = errno;
                close(current); free(copy); errno = saved; return -1;
            }
            close(current);
            current = next;
        }
        part = slash + 1;
    }
    free(copy);
    if (*leaf == NULL) { close(current); return -1; }
    return current;
}

static int ensure_directory(int parent, const char *name)
{
    int created = 0, fd;
    if (mkdirat(parent, name, 0755) == 0) created = 1;
    else if (errno != EEXIST) return -1;
    if (created && fsync(parent) < 0) return -1;
    fd = openat(parent, name,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    return fd;
}

static int blob_directory(int root_fd)
{
    int tm_fd = -1, blobs_fd = -1, result = -1;
    tm_fd = ensure_directory(root_fd, ".tm");
    if (tm_fd < 0) goto done;
    blobs_fd = ensure_directory(tm_fd, "blobs");
    if (blobs_fd < 0) goto done;
    result = ensure_directory(blobs_fd, "sha256");
done:
    if (blobs_fd >= 0) close(blobs_fd);
    if (tm_fd >= 0) close(tm_fd);
    return result;
}

void tm_output_manifest_clear(struct tm_output_manifest *manifest)
{
    size_t i;
    if (manifest == NULL) return;
    for (i = 0; i < manifest->count; i++) free(manifest->entries[i].path);
    free(manifest->entries);
    memset(manifest, 0, sizeof(*manifest));
}

static int add_entry(struct tm_output_manifest *manifest, const char *path,
                     enum tm_output_kind kind, mode_t mode,
                     const char *digest, uint64_t size)
{
    struct tm_output_entry *entries;
    if (manifest->count >= OUTPUT_ENTRY_LIMIT) { errno = E2BIG; return -1; }
    entries = realloc(manifest->entries,
        (manifest->count + 1) * sizeof(*manifest->entries));
    if (entries == NULL) return -1;
    manifest->entries = entries;
    entries = &manifest->entries[manifest->count];
    memset(entries, 0, sizeof(*entries));
    entries->path = strdup(path);
    if (entries->path == NULL) return -1;
    entries->kind = kind;
    entries->mode = (uint32_t)(mode & 0777);
    entries->size = size;
    if (digest != NULL) memcpy(entries->digest, digest, 72);
    manifest->count++;
    return 0;
}

static int verify_existing_blob(int blob_fd, const char *name,
                                const char *expected_digest, uint64_t size)
{
    unsigned char buffer[32768], hash[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *context = NULL;
    struct stat before, after;
    unsigned int hash_length = 0;
    uint64_t total = 0;
    int fd = openat(blob_fd, name,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int result = -1, saved;
    char formatted[72];
    static const char digits[] = "0123456789abcdef";
    size_t i;
    if (fd < 0) return -1;
    if (fstat(fd, &before) < 0 || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || (before.st_mode & 0222) != 0 ||
        before.st_size < 0 || (uint64_t)before.st_size != size) {
        errno = EIO; goto done;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        errno = EIO; goto done;
    }
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (n == 0) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)n) != 1) {
            errno = EIO; goto done;
        }
        total += (uint64_t)n;
    }
    if (fstat(fd, &after) < 0 || !same_version(&before, &after) ||
        total != size || EVP_DigestFinal_ex(context, hash, &hash_length) != 1 ||
        hash_length != 32) { errno = EIO; goto done; }
    memcpy(formatted, "sha256:", 7);
    for (i = 0; i < 32; i++) {
        formatted[7 + i * 2] = digits[hash[i] >> 4];
        formatted[8 + i * 2] = digits[hash[i] & 15];
    }
    formatted[71] = '\0';
    if (strcmp(formatted, expected_digest) != 0) { errno = EIO; goto done; }
    result = 0;
done:
    saved = errno;
    EVP_MD_CTX_free(context);
    close(fd);
    errno = saved;
    return result;
}

int tm_outputs_verify_store(int blob_store_root_fd,
                            const struct tm_output_manifest *manifest)
{
    int blob_fd, result = 0;
    size_t index;
    if (blob_store_root_fd < 0 || manifest == NULL ||
        (manifest->count > 0 && manifest->entries == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (manifest->count == 0) return 0;
    blob_fd = read_blob_directory(blob_store_root_fd);
    if (blob_fd < 0) return -1;
    for (index = 0; index < manifest->count; index++) {
        const struct tm_output_entry *entry = &manifest->entries[index];
        char name[65];
        size_t digit;
        if (entry->kind == TM_OUTPUT_DIRECTORY) continue;
        if (entry->kind != TM_OUTPUT_FILE ||
            strnlen(entry->digest, sizeof(entry->digest)) != 71 ||
            memcmp(entry->digest, "sha256:", 7) != 0) {
            errno = EINVAL;
            result = -1;
            break;
        }
        for (digit = 0; digit < 64; digit++) {
            char value = entry->digest[digit + 7];
            if (!((value >= '0' && value <= '9') ||
                  (value >= 'a' && value <= 'f'))) break;
            name[digit] = value;
        }
        if (digit != 64) {
            errno = EINVAL;
            result = -1;
            break;
        }
        name[64] = '\0';
        if (verify_existing_blob(blob_fd, name, entry->digest,
                                 entry->size) < 0) {
            result = -1;
            break;
        }
    }
    {
        int saved = errno;
        close(blob_fd);
        errno = saved;
    }
    return result;
}

static int publish_blob(int blob_fd, int source_fd, const struct stat *before,
                        char digest[72], uint64_t *size)
{
    unsigned char buffer[32768], hash[EVP_MAX_MD_SIZE];
    EVP_MD_CTX *context = NULL;
    struct stat after;
    unsigned int hash_length = 0;
    uint64_t total = 0;
    unsigned long sequence;
    char temporary[80] = {0}, filename[65];
    static const char digits[] = "0123456789abcdef";
    int temp_fd = -1, temp_created = 0, result = -1, saved;
    size_t i;

    if (!S_ISREG(before->st_mode) || before->st_nlink != 1 ||
        before->st_size < 0) { errno = EOPNOTSUPP; return -1; }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        errno = EIO; goto done;
    }
    sequence = atomic_fetch_add(&stage_sequence, 1);
    if (snprintf(temporary, sizeof(temporary), ".tm-output-%ld-%lu",
                 (long)getpid(), sequence) >= (int)sizeof(temporary)) {
        errno = EOVERFLOW; goto done;
    }
    temp_fd = openat(blob_fd, temporary,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (temp_fd < 0) goto done;
    temp_created = 1;
    for (;;) {
        ssize_t n = read(source_fd, buffer, sizeof(buffer));
        size_t offset = 0;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) goto done;
        if (n == 0) break;
        if (EVP_DigestUpdate(context, buffer, (size_t)n) != 1) {
            errno = EIO; goto done;
        }
        while (offset < (size_t)n) {
            ssize_t written = write(temp_fd, buffer + offset,
                                    (size_t)n - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) { errno = EIO; goto done; }
            offset += (size_t)written;
        }
        if (total > UINT64_MAX - (uint64_t)n) { errno = EOVERFLOW; goto done; }
        total += (uint64_t)n;
    }
    if (fstat(source_fd, &after) < 0 || !same_version(before, &after) ||
        EVP_DigestFinal_ex(context, hash, &hash_length) != 1 || hash_length != 32) {
        errno = EBUSY; goto done;
    }
    if (fchmod(temp_fd, 0444) < 0 || fsync(temp_fd) < 0) goto done;
    if (close(temp_fd) < 0) { temp_fd = -1; goto done; }
    temp_fd = -1;
    memcpy(digest, "sha256:", 7);
    for (i = 0; i < 32; i++) {
        digest[7 + i * 2] = digits[hash[i] >> 4];
        digest[8 + i * 2] = digits[hash[i] & 15];
        filename[i * 2] = digits[hash[i] >> 4];
        filename[i * 2 + 1] = digits[hash[i] & 15];
    }
    digest[71] = '\0';
    filename[64] = '\0';
    if (linkat(blob_fd, temporary, blob_fd, filename, 0) < 0) {
        if (errno != EEXIST ||
            verify_existing_blob(blob_fd, filename, digest, total) < 0)
            goto done;
    }
    if (unlinkat(blob_fd, temporary, 0) < 0) goto done;
    temp_created = 0;
    if (fsync(blob_fd) < 0) goto done;
    *size = total;
    result = 0;
done:
    saved = errno;
    if (temp_fd >= 0) close(temp_fd);
    if (temp_created) unlinkat(blob_fd, temporary, 0);
    EVP_MD_CTX_free(context);
    errno = saved;
    return result;
}

static int path_join(char *output, size_t capacity, const char *parent,
                     const char *name)
{
    int n = snprintf(output, capacity, "%s/%s", parent, name);
    if (n < 0 || (size_t)n >= capacity) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

static int capture_path(int parent_fd, int blob_fd, const char *leaf,
                        const char *relative,
                        struct tm_output_manifest *manifest);

static int capture_directory(int directory_fd, int blob_fd,
                             const char *relative,
                             struct tm_output_manifest *manifest,
                             const struct stat *before)
{
    DIR *directory = NULL;
    int duplicate = dup(directory_fd), result = -1;
    struct stat after;
    if (duplicate < 0) return -1;
    directory = fdopendir(duplicate);
    if (directory == NULL) { close(duplicate); return -1; }
    for (;;) {
        struct dirent *entry;
        char child[OUTPUT_PATH_LIMIT + 1];
        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0) goto done;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (path_join(child, sizeof(child), relative, entry->d_name) < 0 ||
            capture_path(directory_fd, blob_fd, entry->d_name, child,
                         manifest) < 0) goto done;
    }
    if (fstat(directory_fd, &after) < 0 || !same_version(before, &after)) {
        errno = EBUSY; goto done;
    }
    result = 0;
done:
    closedir(directory);
    return result;
}

static int capture_path(int parent_fd, int blob_fd, const char *leaf,
                        const char *relative,
                        struct tm_output_manifest *manifest)
{
    struct stat status;
    if (!valid_relative_path(relative)) { errno = EINVAL; return -1; }
    if (fstatat(parent_fd, leaf, &status, AT_SYMLINK_NOFOLLOW) < 0) return -1;
    if (S_ISDIR(status.st_mode)) {
        int directory = openat(parent_fd, leaf,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        int result;
        if (directory < 0) return -1;
        if (add_entry(manifest, relative, TM_OUTPUT_DIRECTORY,
                      status.st_mode, NULL, 0) < 0) {
            close(directory); return -1;
        }
        result = capture_directory(directory, blob_fd, relative, manifest,
                                   &status);
        close(directory);
        return result;
    }
    if (!S_ISREG(status.st_mode) || status.st_nlink != 1) {
        errno = EOPNOTSUPP; return -1;
    }
    {
        int fd = openat(parent_fd, leaf,
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        char digest[72];
        uint64_t size = 0;
        int result;
        if (fd < 0) return -1;
        if (fstat(fd, &status) < 0 || !S_ISREG(status.st_mode) ||
            status.st_nlink != 1 ||
            publish_blob(blob_fd, fd, &status, digest, &size) < 0) {
            int saved = errno; close(fd); errno = saved; return -1;
        }
        result = add_entry(manifest, relative, TM_OUTPUT_FILE,
                           status.st_mode, digest, size);
        close(fd);
        return result;
    }
}

static int compare_entries(const void *left, const void *right)
{
    const struct tm_output_entry *a = left, *b = right;
    return strcmp(a->path, b->path);
}

static int roots_overlap(const char *left, const char *right)
{
    size_t length = strlen(left);
    return strncmp(left, right, length) == 0 &&
           (right[length] == '\0' || right[length] == '/');
}

int tm_output_roots_validate(const char *const *roots, size_t root_count)
{
    size_t i, j;
    if ((root_count > 0 && roots == NULL) || root_count > OUTPUT_ROOT_LIMIT) {
        errno = EINVAL;
        return -1;
    }
    for (i = 0; i < root_count; i++) {
        if (!valid_relative_path(roots[i])) { errno = EINVAL; return -1; }
        for (j = 0; j < i; j++)
            if (roots_overlap(roots[i], roots[j]) ||
                roots_overlap(roots[j], roots[i])) {
                errno = EINVAL;
                return -1;
            }
    }
    return 0;
}

int tm_outputs_capture_to_store(int repository_root_fd, int blob_store_root_fd,
                                const char *const *roots, size_t root_count,
                                struct tm_output_manifest *manifest)
{
    int blob_fd = -1, result = -1, saved;
    size_t i;
    if (repository_root_fd < 0 || blob_store_root_fd < 0 || manifest == NULL ||
        (root_count > 0 && roots == NULL) || root_count > OUTPUT_ROOT_LIMIT) {
        errno = EINVAL; return -1;
    }
    tm_output_manifest_clear(manifest);
    if (root_count == 0) return 0;
    if (tm_output_roots_validate(roots, root_count) < 0) goto done;
    blob_fd = blob_directory(blob_store_root_fd);
    if (blob_fd < 0) goto done;
    for (i = 0; i < root_count; i++) {
        char *leaf = NULL;
        int parent = open_parent(repository_root_fd, roots[i], &leaf);
        if (parent < 0) { free(leaf); goto done; }
        result = capture_path(parent, blob_fd, leaf, roots[i], manifest);
        saved = errno;
        close(parent);
        free(leaf);
        errno = saved;
        if (result < 0) goto done;
    }
    if (manifest->count > 1)
        qsort(manifest->entries, manifest->count,
              sizeof(*manifest->entries), compare_entries);
    for (i = 1; i < manifest->count; i++)
        if (strcmp(manifest->entries[i - 1].path,
                   manifest->entries[i].path) == 0) {
            errno = EEXIST; goto done;
        }
    result = 0;
done:
    saved = errno;
    if (blob_fd >= 0) close(blob_fd);
    if (result < 0) tm_output_manifest_clear(manifest);
    errno = saved;
    return result;
}

int tm_outputs_capture(int repository_root_fd, const char *const *roots,
                       size_t root_count, struct tm_output_manifest *manifest)
{
    return tm_outputs_capture_to_store(repository_root_fd, repository_root_fd,
                                       roots, root_count, manifest);
}

int tm_outputs_restore_from_store(
    int repository_root_fd, int blob_store_root_fd, const char *const *roots,
    size_t root_count, const struct tm_output_manifest *manifest)
{
    int blobfd = -1, result = -1, saved;
    size_t i, j;
    if (repository_root_fd < 0 || blob_store_root_fd < 0 || manifest == NULL ||
        (root_count > 0 && roots == NULL) || root_count > OUTPUT_ROOT_LIMIT ||
        (manifest->count > 0 && manifest->entries == NULL)) {
        errno = EINVAL; return -1;
    }
    if (root_count == 0) {
        if (manifest->count != 0) { errno = EINVAL; return -1; }
        return 0;
    }
    for (i = 0; i < root_count; i++) {
        if (!valid_relative_path(roots[i])) { errno = EINVAL; goto done; }
        for (j = 0; j < i; j++)
            if (roots_overlap(roots[i], roots[j]) || roots_overlap(roots[j], roots[i])) {
                errno = EINVAL; goto done;
            }
    }
    for (i = 0; i < manifest->count; i++) {
        const struct tm_output_entry *entry = &manifest->entries[i];
        size_t coverage = 0;
        if (!valid_relative_path(entry->path) || entry->mode > 0777 ||
            (i && strcmp(manifest->entries[i-1].path, entry->path) >= 0)) {
            errno = EINVAL; goto done;
        }
        for (j = 0; j < root_count; j++)
            if (root_contains(roots[j], entry->path)) coverage++;
        if (coverage != 1) { errno = EINVAL; goto done; }
        if (entry->kind == TM_OUTPUT_FILE) {
            if (strlen(entry->digest) != 71 || strncmp(entry->digest, "sha256:", 7) != 0 ||
                entry->size > UINT64_C(9007199254740991)) { errno = EINVAL; goto done; }
            for (j = 0; j < 32; j++) {
                char a = entry->digest[7 + j * 2], b = entry->digest[8 + j * 2];
                if (!((a >= '0' && a <= '9') || (a >= 'a' && a <= 'f')) ||
                    !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f'))) {
                    errno = EINVAL; goto done;
                }
            }
        } else if (entry->kind != TM_OUTPUT_DIRECTORY || entry->size != 0 ||
                   entry->digest[0] != '\0') { errno = EINVAL; goto done; }
    }
    for (i = 0; i < root_count; i++) {
        int found = 0;
        for (j = 0; j < manifest->count; j++) {
            if (strcmp(roots[i], manifest->entries[j].path) == 0) {
                found = 1;
                if (manifest->entries[j].kind == TM_OUTPUT_FILE)
                    for (size_t k = j + 1; k < manifest->count; k++)
                        if (root_contains(roots[i], manifest->entries[k].path)) {
                            errno = EINVAL; goto done;
                        }
                break;
            }
        }
        if (!found) { errno = EINVAL; goto done; }
    }
    if (root_count == 0 && manifest->count != 0) { errno = EINVAL; goto done; }
    blobfd = read_blob_directory(blob_store_root_fd);
    if (blobfd < 0) goto done;
    /* Verify every blob before any owned destination is replaced. */
    for (i = 0; i < manifest->count; i++) {
        const struct tm_output_entry *entry = &manifest->entries[i];
        char name[65];
        if (entry->kind != TM_OUTPUT_FILE) continue;
        for (j = 0; j < 32; j++) {
            name[j * 2] = entry->digest[7 + j * 2];
            name[j * 2 + 1] = entry->digest[8 + j * 2];
        }
        name[64] = '\0';
        if (verify_existing_blob(blobfd, name, entry->digest, entry->size) < 0) goto done;
    }
    for (i = 0; i < root_count; i++)
        if (restore_staged_root(repository_root_fd, blobfd, roots[i], manifest) < 0) goto done;
    result = 0;
done:
    saved = errno;
    if (blobfd >= 0) close(blobfd);
    errno = saved;
    return result;
}

int tm_outputs_restore(int repository_root_fd, const char *const *roots,
                      size_t root_count,
                      const struct tm_output_manifest *manifest)
{
    return tm_outputs_restore_from_store(repository_root_fd,
        repository_root_fd, roots, root_count, manifest);
}
