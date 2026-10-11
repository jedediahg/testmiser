#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/attempt.h"
#include "tm/digest.h"
#include "tm/local_store.h"

static int private_directory(int parent, const char *name)
{
    struct stat status;
    int created = 0;
    int fd;
    if (mkdirat(parent, name, 0700) == 0) created = 1;
    else if (errno != EEXIST) return -1;
    if (created && fsync(parent) < 0) return -1;
    fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &status) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0) {
        close(fd); errno = EACCES; return -1;
    }
    return fd;
}

static int valid_digest(const char *value)
{
    size_t i;
    if (value == NULL || strlen(value) != 71 || memcmp(value, "sha256:", 7))
        return 0;
    for (i = 7; i < 71; i++)
        if (!((value[i] >= '0' && value[i] <= '9') ||
              (value[i] >= 'a' && value[i] <= 'f'))) return 0;
    return 1;
}

static int valid_marker_name(const char *name)
{
    size_t index;
    if (!((strlen(name) == 71 && strcmp(name + 64, ".failed") == 0) ||
          (strlen(name) == 76 && strcmp(name + 64, ".quarantined") == 0)))
        return 0;
    for (index = 0; index < 64; index++)
        if (!((name[index] >= '0' && name[index] <= '9') ||
              (name[index] >= 'a' && name[index] <= 'f'))) return 0;
    return 1;
}

static int valid_repository_id(const char *value)
{
    size_t index, length;
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

static int marker(int dir, const char *name)
{
    int fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                    O_NOFOLLOW, 0600);
    if (fd < 0) return errno == EEXIST ? 0 : -1;
    {
        int failed = fsync(fd) < 0;
        int saved = errno;
        if (close(fd) < 0 && !failed) { failed = 1; saved = errno; }
        if (!failed && fsync(dir) < 0) { failed = 1; saved = errno; }
        if (failed) { errno = saved; return -1; }
    }
    return 0;
}

static int checked_marker(int dir, const char *name)
{
    struct stat st;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        st.st_nlink != 1 || (st.st_mode & 077) != 0 || st.st_size != 0) {
        close(fd); errno = EACCES; return -1;
    }
    close(fd);
    return 1;
}

static int remove_marker(int dir, const char *name)
{
    if (unlinkat(dir, name, 0) < 0 && errno != ENOENT) return -1;
    return fsync(dir);
}

static int add_block(struct tm_attempt_state *state, const char *digest)
{
    char **items;
    size_t i;
    for (i = 0; i < state->blocked_count; i++)
        if (strcmp(state->blocked_fingerprints[i], digest) == 0) return 0;
    items = realloc(state->blocked_fingerprints,
                    (state->blocked_count + 1) * sizeof(*items));
    if (items == NULL) return -1;
    state->blocked_fingerprints = items;
    items[state->blocked_count] = strdup(digest);
    if (items[state->blocked_count] == NULL) return -1;
    state->blocked_count++;
    return 0;
}

int tm_attempt_state_open_default(const char *repository_id,
                                  const char *command_fingerprint,
                                  const char *profile_digest,
                                  const char *context_digest,
                                  struct tm_attempt_state *state)
{
    const char *fields[] = {"testmiser-attempt-v1", repository_id,
        command_fingerprint, profile_digest, context_digest};
    unsigned char buffer[1024];
    size_t offset = 0, i;
    char digest[65], slot[65];
    int store = -1, attempts = -1, directory = -1;
    DIR *stream = NULL;
    struct dirent *entry;
    if (state == NULL || !valid_repository_id(repository_id) ||
        !valid_digest(command_fingerprint) || !valid_digest(profile_digest) ||
        !valid_digest(context_digest)) { errno = EINVAL; return -1; }
    memset(state, 0, sizeof(*state)); state->directory_fd = -1;
    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        size_t n = strlen(fields[i]);
        if (n > UINT32_MAX || offset > sizeof(buffer) - n - 4) {
            errno = EOVERFLOW; goto fail;
        }
        buffer[offset++] = (unsigned char)(n >> 24);
        buffer[offset++] = (unsigned char)(n >> 16);
        buffer[offset++] = (unsigned char)(n >> 8);
        buffer[offset++] = (unsigned char)n;
        memcpy(buffer + offset, fields[i], n); offset += n;
    }
    if (tm_sha256_bytes(buffer, offset, digest) < 0) goto fail;
    memcpy(slot, digest, sizeof(slot));
    if (tm_local_store_open_default(&store) < 0) goto fail;
    attempts = private_directory(store, "attempts");
    if (attempts < 0) goto fail;
    directory = private_directory(attempts, slot);
    if (directory < 0) goto fail;
    state->directory_fd = directory; directory = -1;
    {
        int pending = checked_marker(state->directory_fd, "running");
        if (pending < 0) goto fail;
        if (pending) {
            if (marker(state->directory_fd, "block-all") < 0 ||
                remove_marker(state->directory_fd, "running") < 0) goto fail;
            state->stale_running = 1;
        }
        state->blocked_all = checked_marker(state->directory_fd, "block-all");
        if (state->blocked_all < 0) goto fail;
    }
    {
        int scan_fd = openat(state->directory_fd, ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (scan_fd < 0) goto fail;
        stream = fdopendir(scan_fd);
        if (stream == NULL) { close(scan_fd); goto fail; }
    }
    for (;;) {
        size_t n;
        char value[72];
        int present;
        errno = 0;
        entry = readdir(stream);
        if (entry == NULL) {
            if (errno != 0) goto fail;
            break;
        }
        n = strlen(entry->d_name);
        if (n != 0 && !valid_marker_name(entry->d_name)) {
            if ((n >= 7 && strcmp(entry->d_name + n - 7, ".failed") == 0) ||
                (n >= 12 && strcmp(entry->d_name + n - 12, ".quarantined") == 0)) {
                errno = EINVAL; goto fail;
            }
            continue;
        }
        if (n == 0) continue;
        (void)snprintf(value, sizeof(value), "sha256:%.*s", 64,
                       entry->d_name);
        present = checked_marker(state->directory_fd, entry->d_name);
        if (present != 1 || add_block(state, value) < 0) goto fail;
    }
    closedir(stream); stream = NULL;
    close(attempts); close(store);
    return 0;
fail:
    {
        int saved = errno;
        if (stream != NULL) closedir(stream);
        if (directory >= 0) close(directory);
        if (state->directory_fd >= 0) close(state->directory_fd);
        state->directory_fd = -1;
        if (attempts >= 0) close(attempts);
        if (store >= 0) close(store);
        tm_attempt_state_clear(state);
        errno = saved;
    }
    return -1;
}

int tm_attempt_state_begin(struct tm_attempt_state *state)
{
    if (state == NULL || state->directory_fd < 0) { errno = EINVAL; return -1; }
    return marker(state->directory_fd, "running");
}

int tm_attempt_state_finish(struct tm_attempt_state *state,
                            enum tm_attempt_outcome outcome,
                            const char *verification_fingerprint)
{
    char name[80];
    if (state == NULL || state->directory_fd < 0 ||
        (outcome != TM_ATTEMPT_RUN_ONLY && outcome != TM_ATTEMPT_FAILED &&
         outcome != TM_ATTEMPT_QUARANTINED &&
         outcome != TM_ATTEMPT_ELIGIBLE_SUCCESS) ||
        (verification_fingerprint != NULL &&
         !valid_digest(verification_fingerprint)) ||
        (outcome == TM_ATTEMPT_ELIGIBLE_SUCCESS &&
         verification_fingerprint == NULL)) { errno = EINVAL; return -1; }
    if (outcome == TM_ATTEMPT_FAILED || outcome == TM_ATTEMPT_QUARANTINED) {
        if (verification_fingerprint == NULL) {
            if (marker(state->directory_fd, "block-all") < 0) return -1;
            state->blocked_all = 1;
        } else if (snprintf(name, sizeof(name), "%s.%s", verification_fingerprint + 7,
                       outcome == TM_ATTEMPT_FAILED ? "failed" : "quarantined") >=
                   (int)sizeof(name) || marker(state->directory_fd, name) < 0)
            return -1;
    } else if (outcome == TM_ATTEMPT_ELIGIBLE_SUCCESS) {
        char quarantined[80];
        if (remove_marker(state->directory_fd, "block-all") < 0) return -1;
        if (snprintf(name, sizeof(name), "%s.failed", verification_fingerprint + 7) >=
            (int)sizeof(name) || remove_marker(state->directory_fd, name) < 0) return -1;
        if (snprintf(quarantined, sizeof(quarantined), "%s.quarantined",
                     verification_fingerprint + 7) >=
                (int)sizeof(quarantined) ||
            remove_marker(state->directory_fd, quarantined) < 0) return -1;
        for (size_t i = 0; i < state->blocked_count; i++) {
            if (strcmp(state->blocked_fingerprints[i], verification_fingerprint) == 0) {
                free(state->blocked_fingerprints[i]);
                memmove(&state->blocked_fingerprints[i],
                        &state->blocked_fingerprints[i + 1],
                        (state->blocked_count - i - 1) *
                            sizeof(*state->blocked_fingerprints));
                state->blocked_count--;
                break;
            }
        }
    }
    if (outcome != TM_ATTEMPT_RUN_ONLY || !state->stale_running)
        return remove_marker(state->directory_fd, "running");
    return 0;
}

int tm_attempt_state_blocks(const struct tm_attempt_state *state,
                            const char *verification_fingerprint)
{
    size_t i;
    char name[80];
    int found;
    if (state == NULL || !valid_digest(verification_fingerprint)) return 1;
    if (state->blocked_all) return 1;
    for (i = 0; i < state->blocked_count; i++)
        if (strcmp(state->blocked_fingerprints[i], verification_fingerprint) == 0)
            return 1;
    if (snprintf(name, sizeof(name), "%s.quarantined",
                 verification_fingerprint + 7) >= (int)sizeof(name)) return 1;
    found = checked_marker(state->directory_fd, name);
    return found != 0;
}

static void remove_blocked_memory(struct tm_attempt_state *state,
                                  const char *fingerprint)
{
    size_t i = 0;
    while (i < state->blocked_count) {
        if (fingerprint != NULL &&
            strcmp(state->blocked_fingerprints[i], fingerprint) != 0) {
            i++;
            continue;
        }
        free(state->blocked_fingerprints[i]);
        memmove(&state->blocked_fingerprints[i],
                &state->blocked_fingerprints[i + 1],
                (state->blocked_count - i - 1) *
                    sizeof(*state->blocked_fingerprints));
        state->blocked_count--;
    }
}

static int attempt_marker_name(const char *name)
{
    size_t length = strlen(name);
    return strcmp(name, "running") == 0 || strcmp(name, "block-all") == 0 ||
        (length == 71 && (strcmp(name + 64, ".failed") == 0)) ||
        (length == 76 && strcmp(name + 64, ".quarantined") == 0);
}

int tm_attempt_state_resolve(struct tm_attempt_state *state,
                             const char *verification_fingerprint)
{
    if (state == NULL || state->directory_fd < 0 ||
        (verification_fingerprint != NULL &&
         !valid_digest(verification_fingerprint))) { errno = EINVAL; return -1; }
    if (verification_fingerprint != NULL) {
        char failed[80], quarantined[80];
        if (snprintf(failed, sizeof(failed), "%s.failed",
                     verification_fingerprint + 7) >= (int)sizeof(failed) ||
            snprintf(quarantined, sizeof(quarantined), "%s.quarantined",
                     verification_fingerprint + 7) >= (int)sizeof(quarantined) ||
            remove_marker(state->directory_fd, failed) < 0 ||
            remove_marker(state->directory_fd, quarantined) < 0) return -1;
        remove_blocked_memory(state, verification_fingerprint);
        return 0;
    }
    {
        int duplicate = openat(state->directory_fd, ".",
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        DIR *directory = duplicate < 0 ? NULL : fdopendir(duplicate);
        struct dirent *entry;
        if (directory == NULL) {
            if (duplicate >= 0) close(duplicate);
            return -1;
        }
        for (;;) {
            int present;
            errno = 0;
            entry = readdir(directory);
            if (entry == NULL) {
                if (errno != 0) {
                    int saved = errno;
                    closedir(directory); errno = saved; return -1;
                }
                break;
            }
            if (!attempt_marker_name(entry->d_name)) continue;
            present = checked_marker(state->directory_fd, entry->d_name);
            if (present < 0 || (present > 0 &&
                remove_marker(state->directory_fd, entry->d_name) < 0)) {
                int saved = errno;
                closedir(directory); errno = saved; return -1;
            }
        }
        closedir(directory);
    }
    state->blocked_all = 0;
    state->stale_running = 0;
    remove_blocked_memory(state, NULL);
    return 0;
}

void tm_attempt_state_clear(struct tm_attempt_state *state)
{
    size_t i;
    if (state == NULL) return;
    if (state->directory_fd >= 0) close(state->directory_fd);
    for (i = 0; i < state->blocked_count; i++) free(state->blocked_fingerprints[i]);
    free(state->blocked_fingerprints);
    memset(state, 0, sizeof(*state)); state->directory_fd = -1;
}
