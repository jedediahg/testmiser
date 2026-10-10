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

int tm_open_directory_without_symlinks(const char *path)
{
    char *copy, *save = NULL, *component;
    int current, saved;
    if (path == NULL || path[0] != '/') { errno = EINVAL; return -1; }
    copy = strdup(path);
    if (copy == NULL) return -1;
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current < 0) {
        saved = errno;
        free(copy);
        errno = saved;
        return -1;
    }
    component = strtok_r(copy, "/", &save);
    while (component != NULL) {
        int next;
        if (strcmp(component, ".") == 0 || strcmp(component, "..") == 0) {
            errno = EINVAL;
            goto fail;
        }
        next = openat(current, component,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) goto fail;
        close(current);
        current = next;
        component = strtok_r(NULL, "/", &save);
    }
    free(copy);
    return current;
fail:
    saved = errno;
    close(current);
    free(copy);
    errno = saved;
    return -1;
}

static int open_or_create_final_directory(const char *path)
{
    char *copy = NULL, *leaf = NULL, *slash;
    size_t length;
    int parent = -1, directory = -1, saved;

    copy = strdup(path);
    if (copy == NULL) return -1;
    length = strlen(copy);
    while (length > 1 && copy[length - 1] == '/')
        copy[--length] = '\0';
    slash = strrchr(copy, '/');
    if (slash == NULL || slash[1] == '\0') {
        errno = EINVAL;
        goto fail;
    }
    leaf = strdup(slash + 1);
    if (leaf == NULL) goto fail;
    if (strcmp(leaf, ".") == 0 || strcmp(leaf, "..") == 0) {
        errno = EINVAL;
        goto fail;
    }
    if (slash == copy) copy[1] = '\0';
    else *slash = '\0';
    parent = tm_open_directory_without_symlinks(copy);
    if (parent < 0) goto fail;
    if (mkdirat(parent, leaf, 0700) < 0 && errno != EEXIST) goto fail;
    directory = openat(parent, leaf,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) goto fail;
    close(parent);
    free(leaf);
    free(copy);
    return directory;

fail:
    saved = errno;
    if (directory >= 0) close(directory);
    if (parent >= 0) close(parent);
    free(leaf);
    free(copy);
    errno = saved;
    return -1;
}

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
    struct stat status;
    int root = -1, app = -1, store = -1, saved;

    if (cache_root == NULL || store_root_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    *store_root_fd = -1;
    root = tm_open_directory_without_symlinks(cache_root);
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
    return 0;

fail:
    saved = errno;
    if (store >= 0) close(store);
    if (app >= 0) close(app);
    if (root >= 0) close(root);
    errno = saved;
    return -1;
}

int tm_user_cache_root(char **cache_root)
{
    const char *xdg_cache = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    char *candidate = NULL;
    size_t length;
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
    descriptor = tm_open_directory_without_symlinks(candidate);
    if (descriptor < 0 && xdg_cache != NULL && xdg_cache[0] != '\0' &&
        errno == ENOENT)
        descriptor = open_or_create_final_directory(candidate);
    if (descriptor < 0) goto fail;
    if (fstat(descriptor, &status) < 0) goto fail;
    if (!S_ISDIR(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 022) != 0) {
        errno = EACCES;
        goto fail;
    }
    close(descriptor);
    *cache_root = candidate;
    return 0;

fail:
    saved = errno;
    if (descriptor >= 0) close(descriptor);
    free(candidate);
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

int tm_shared_store_open_configured(int *store_root_fd)
{
    const char *configured = getenv("TM_SHARED_STORE");
    struct stat status;
    int root = -1, app = -1, store = -1, saved;

    if (store_root_fd == NULL) { errno = EINVAL; return -1; }
    *store_root_fd = -1;
    if (configured == NULL || configured[0] == '\0') return 1;
    if (configured[0] != '/') { errno = EINVAL; return -1; }
    root = tm_open_directory_without_symlinks(configured);
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
    close(app);
    close(root);
    return 0;

fail:
    saved = errno;
    if (store >= 0) close(store);
    if (app >= 0) close(app);
    if (root >= 0) close(root);
    errno = saved;
    return -1;
}
