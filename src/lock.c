#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "tm/digest.h"
#include "tm/lock.h"
#include "tm/local_store.h"

static int valid_digest(const char *value)
{
    size_t index;
    if (value == NULL || strlen(value) != 71 ||
        memcmp(value, "sha256:", 7) != 0) return 0;
    for (index = 7; index < 71; index++)
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    return 1;
}

static int valid_repository_id(const char *value)
{
    size_t index;
    size_t length;
    if (value == NULL || (length = strlen(value)) == 0 || length > 128 ||
        !((value[0] >= 'a' && value[0] <= 'z') ||
          (value[0] >= '0' && value[0] <= '9'))) return 0;
    for (index = 1; index < length; index++)
        if (!((value[index] >= 'a' && value[index] <= 'z') ||
              (value[index] >= '0' && value[index] <= '9') ||
              value[index] == '.' || value[index] == '_' ||
              value[index] == '-')) return 0;
    return 1;
}

static int append_field(unsigned char *buffer, size_t capacity, size_t *offset,
                        const char *value)
{
    size_t length = strlen(value);
    size_t index;
    if (length > UINT32_MAX || *offset > capacity ||
        capacity - *offset < length + 4) {
        errno = EOVERFLOW;
        return -1;
    }
    buffer[(*offset)++] = (unsigned char)(length >> 24);
    buffer[(*offset)++] = (unsigned char)(length >> 16);
    buffer[(*offset)++] = (unsigned char)(length >> 8);
    buffer[(*offset)++] = (unsigned char)length;
    for (index = 0; index < length; index++)
        buffer[(*offset)++] = (unsigned char)value[index];
    return 0;
}

static int open_private_directory(int parent, const char *name)
{
    struct stat status;
    int directory;
    if (mkdirat(parent, name, 0700) < 0 && errno != EEXIST) return -1;
    directory = openat(parent, name,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return -1;
    if (fstat(directory, &status) < 0) {
        int saved = errno;
        close(directory);
        errno = saved;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0) {
        close(directory);
        errno = EACCES;
        return -1;
    }
    return directory;
}

int tm_lock_acquire(const char *cache_root, const char *repository_id,
                    const char *command_fingerprint,
                    const char *profile_digest, const char *context_digest,
                    struct tm_lock *lock)
{
    static const unsigned char domain[] = "tm-local-lock-v1\0";
    unsigned char material[sizeof(domain) - 1 + 4 + 128 + 3 * (4 + 71)];
    size_t offset = sizeof(domain) - 1;
    char digest[65];
    char filename[80];
    struct stat status;
    int root = -1, app = -1, locks = -1, descriptor = -1, saved;

    if (cache_root == NULL || !valid_repository_id(repository_id) ||
        !valid_digest(command_fingerprint) || !valid_digest(profile_digest) ||
        !valid_digest(context_digest) || lock == NULL) {
        errno = EINVAL;
        return -1;
    }
    lock->fd = -1;
    memcpy(material, domain, offset);
    if (append_field(material, sizeof(material), &offset, repository_id) < 0 ||
        append_field(material, sizeof(material), &offset,
                     command_fingerprint) < 0 ||
        append_field(material, sizeof(material), &offset, profile_digest) < 0 ||
        append_field(material, sizeof(material), &offset, context_digest) < 0 ||
        tm_sha256_bytes(material, offset, digest) < 0) return -1;
    if (snprintf(filename, sizeof(filename), "%s.lock", digest) >=
        (int)sizeof(filename)) {
        errno = EOVERFLOW;
        return -1;
    }
    root = tm_open_directory_without_symlinks(cache_root);
    if (root < 0) goto fail;
    if (fstat(root, &status) < 0) goto fail;
    if (status.st_uid != getuid() || (status.st_mode & 022) != 0) {
        errno = EACCES;
        goto fail;
    }
    app = open_private_directory(root, "testmiser");
    if (app < 0) goto fail;
    locks = open_private_directory(app, "locks");
    if (locks < 0) goto fail;
    descriptor = openat(locks, filename,
                        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) goto fail;
    if (fstat(descriptor, &status) < 0) goto fail;
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0 || status.st_nlink != 1) {
        errno = EACCES;
        goto fail;
    }
    while (flock(descriptor, LOCK_EX) < 0) {
        if (errno == EINTR) continue;
        goto fail;
    }
    lock->fd = descriptor;
    descriptor = -1;
    close(locks);
    close(app);
    close(root);
    return 0;

fail:
    saved = errno;
    if (descriptor >= 0) close(descriptor);
    if (locks >= 0) close(locks);
    if (app >= 0) close(app);
    if (root >= 0) close(root);
    errno = saved;
    return -1;
}

int tm_lock_acquire_store(int store_root_fd, const char *repository_id,
                          const char *command_fingerprint,
                          const char *profile_digest,
                          const char *context_digest, struct tm_lock *lock)
{
    static const unsigned char domain[] = "tm-shared-lock-v1\0";
    unsigned char material[sizeof(domain) - 1 + 4 + 128 + 3 * (4 + 71)];
    size_t offset = sizeof(domain) - 1;
    char digest[65];
    char filename[80];
    struct stat status;
    int locks = -1, descriptor = -1, saved;

    if (store_root_fd < 0 || !valid_repository_id(repository_id) ||
        !valid_digest(command_fingerprint) || !valid_digest(profile_digest) ||
        !valid_digest(context_digest) || lock == NULL) {
        errno = EINVAL;
        return -1;
    }
    lock->fd = -1;
    if (fstat(store_root_fd, &status) < 0) return -1;
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0) {
        errno = EACCES;
        return -1;
    }
    memcpy(material, domain, offset);
    if (append_field(material, sizeof(material), &offset, repository_id) < 0 ||
        append_field(material, sizeof(material), &offset,
                     command_fingerprint) < 0 ||
        append_field(material, sizeof(material), &offset, profile_digest) < 0 ||
        append_field(material, sizeof(material), &offset, context_digest) < 0 ||
        tm_sha256_bytes(material, offset, digest) < 0) return -1;
    if (snprintf(filename, sizeof(filename), "%s.lock", digest) >=
        (int)sizeof(filename)) {
        errno = EOVERFLOW;
        return -1;
    }
    locks = open_private_directory(store_root_fd, "locks");
    if (locks < 0) goto fail;
    descriptor = openat(locks, filename,
                        O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) goto fail;
    if (fstat(descriptor, &status) < 0) goto fail;
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0 || status.st_nlink != 1) {
        errno = EACCES;
        goto fail;
    }
    while (flock(descriptor, LOCK_EX) < 0) {
        if (errno == EINTR) continue;
        goto fail;
    }
    lock->fd = descriptor;
    descriptor = -1;
    close(locks);
    return 0;

fail:
    saved = errno;
    if (descriptor >= 0) close(descriptor);
    if (locks >= 0) close(locks);
    errno = saved;
    return -1;
}

int tm_lock_acquire_default(const char *repository_id,
                            const char *command_fingerprint,
                            const char *profile_digest,
                            const char *context_digest,
                            struct tm_lock *lock)
{
    char *cache_root = NULL;
    int result, saved;
    if (tm_user_cache_root(&cache_root) < 0) return -1;
    result = tm_lock_acquire(cache_root, repository_id, command_fingerprint,
                             profile_digest, context_digest, lock);
    saved = errno;
    free(cache_root);
    errno = saved;
    return result;
}

void tm_lock_release(struct tm_lock *lock)
{
    if (lock == NULL || lock->fd < 0) return;
    close(lock->fd);
    lock->fd = -1;
}
