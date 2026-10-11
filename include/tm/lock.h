#ifndef TM_LOCK_H
#define TM_LOCK_H

struct tm_lock {
    int fd;
};

/* Acquire a blocking user-store lock keyed by repository, command, profile,
 * and context identity. cache_root must be a caller-owned private cache root. */
int tm_lock_acquire(const char *cache_root, const char *repository_id,
                    const char *command_fingerprint,
                    const char *profile_digest, const char *context_digest,
                    struct tm_lock *lock);
int tm_lock_acquire_default(const char *repository_id,
                            const char *command_fingerprint,
                            const char *profile_digest,
                            const char *context_digest,
                            struct tm_lock *lock);
/* Acquire the same slot under the configured shared result store, allowing
 * clients on a coherent shared filesystem to serialize cold misses. */
int tm_lock_acquire_store(int store_root_fd, const char *repository_id,
                          const char *command_fingerprint,
                          const char *profile_digest,
                          const char *context_digest, struct tm_lock *lock);
void tm_lock_release(struct tm_lock *lock);

/* Serialize publication into one checkout's .tm/results tree with
 * `tm clean --records`. The lock is opened without following .tm or lock-file
 * symlinks and is shared by publishers/cleaners using the same repository. */
int tm_lock_acquire_repository_results(int repository_fd,
                                      struct tm_lock *lock);

#endif
