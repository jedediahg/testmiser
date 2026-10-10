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
void tm_lock_release(struct tm_lock *lock);

#endif
