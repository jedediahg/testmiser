#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/local_store.h"

static int open_private_directory(int parent, const char *name)
{
    struct stat status;
    int descriptor;
    if (mkdirat(parent, name, 0700) < 0 && errno != EEXIST) return -1;
    descriptor = openat(parent, name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &status) < 0) {
        int saved = errno;
        close(descriptor);
        errno = saved;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0) {
        close(descriptor);
        errno = EACCES;
        return -1;
    }
    return descriptor;
}

int tm_local_store_open(const char *cache_root, int *store_root_fd)
{
    char *canonical_root = NULL;
    struct stat status;
    int root = -1, app = -1, store = -1, saved;

    if (cache_root == NULL || store_root_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    *store_root_fd = -1;
    canonical_root = realpath(cache_root, NULL);
    if (canonical_root == NULL) return -1;
    root = open(canonical_root,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) goto fail;
    if (fstat(root, &status) < 0) goto fail;
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 022) != 0) {
        errno = EACCES;
        goto fail;
    }
    app = open_private_directory(root, "testmiser");
    if (app < 0) goto fail;
    store = open_private_directory(app, "store");
    if (store < 0) goto fail;
    *store_root_fd = store;
    store = -1;
    close(app);
    close(root);
    free(canonical_root);
    return 0;

fail:
    saved = errno;
    if (store >= 0) close(store);
    if (app >= 0) close(app);
    if (root >= 0) close(root);
    free(canonical_root);
    errno = saved;
    return -1;
}

int tm_user_cache_root(char **cache_root)
{
    const char *xdg_cache = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    char *candidate = NULL;
    size_t length;
    char *canonical_root;
    struct stat status;
    int descriptor = -1, saved;

    if (cache_root == NULL) { errno = EINVAL; return -1; }
    *cache_root = NULL;
    if (xdg_cache != NULL && xdg_cache[0] != '\0') {
        if (xdg_cache[0] != '/') { errno = EINVAL; return -1; }
        candidate = strdup(xdg_cache);
        if (candidate == NULL) return -1;
    } else {
        if (home == NULL || home[0] != '/') { errno = ENOENT; return -1; }
        length = strlen(home);
        if (length > SIZE_MAX - sizeof("/.cache")) {
            errno = EOVERFLOW;
            return -1;
        }
        candidate = malloc(length + sizeof("/.cache"));
        if (candidate == NULL) return -1;
        (void)snprintf(candidate, length + sizeof("/.cache"), "%s/.cache",
                       home);
        if (mkdir(candidate, 0700) < 0 && errno != EEXIST) {
            int saved = errno;
            free(candidate);
            errno = saved;
            return -1;
        }
    }
    canonical_root = realpath(candidate, NULL);
    free(candidate);
    if (canonical_root == NULL) return -1;
    descriptor = open(canonical_root,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) goto fail;
    if (fstat(descriptor, &status) < 0) goto fail;
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 022) != 0) {
        errno = EACCES;
        goto fail;
    }
    close(descriptor);
    *cache_root = canonical_root;
    return 0;

fail:
    saved = errno;
    if (descriptor >= 0) close(descriptor);
    free(canonical_root);
    errno = saved;
    return -1;
}

int tm_local_store_open_default(int *store_root_fd)
{
    char *cache_root = NULL;
    int result;

    if (store_root_fd == NULL) { errno = EINVAL; return -1; }
    *store_root_fd = -1;
    if (tm_user_cache_root(&cache_root) < 0) return -1;
    result = tm_local_store_open(cache_root, store_root_fd);
    free(cache_root);
    return result;
}
