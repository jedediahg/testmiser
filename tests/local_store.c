#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/local_store.h"

int main(void)
{
    char cache[] = "/tmp/tm-local-store-XXXXXX";
    char hostile[] = "/tmp/tm-local-store-hostile-XXXXXX";
    char home[] = "/tmp/tm-local-store-home-XXXXXX";
    char app_path[256], store_path[512], store_link_path[256];
    char new_xdg[256] = {0};
    struct stat first_status, second_status;
    const char *current_xdg = getenv("XDG_CACHE_HOME");
    const char *current_home = getenv("HOME");
    const char *current_shared = getenv("TM_SHARED_STORE");
    char *saved_xdg = current_xdg == NULL ? NULL : strdup(current_xdg);
    char *saved_home = current_home == NULL ? NULL : strdup(current_home);
    char *saved_shared = current_shared == NULL ? NULL : strdup(current_shared);
    int had_xdg = current_xdg != NULL, had_home = current_home != NULL;
    int had_shared = current_shared != NULL;
    int first = -1, second = -1, default_fd = -1, rejected = -1;
    int shared_fd = -1, status = 1;

    if ((had_xdg && saved_xdg == NULL) || (had_home && saved_home == NULL) ||
        (had_shared && saved_shared == NULL) ||
        mkdtemp(cache) == NULL || mkdtemp(hostile) == NULL ||
        tm_local_store_open(cache, &first) < 0 ||
        tm_local_store_open(cache, &second) < 0 ||
        fstat(first, &first_status) < 0 || fstat(second, &second_status) < 0 ||
        first_status.st_ino != second_status.st_ino ||
        first_status.st_dev != second_status.st_dev ||
        (first_status.st_mode & 077) != 0 || first_status.st_uid != getuid())
        goto done;
    if (unsetenv("TM_SHARED_STORE") < 0 ||
        tm_shared_store_open_configured(&shared_fd) != 1 || shared_fd >= 0 ||
        setenv("TM_SHARED_STORE", cache, 1) < 0 ||
        tm_shared_store_open_configured(&shared_fd) < 0 ||
        fstat(shared_fd, &second_status) < 0 ||
        first_status.st_ino != second_status.st_ino ||
        first_status.st_dev != second_status.st_dev) goto done;
    close(shared_fd); shared_fd = -1;
    if (setenv("TM_SHARED_STORE", "relative-store", 1) < 0 ||
        tm_shared_store_open_configured(&rejected) == 0 || rejected >= 0)
        goto done;
    if (setenv("TM_SHARED_STORE", cache, 1) < 0 || chmod(cache, 0775) < 0 ||
        tm_shared_store_open_configured(&rejected) == 0 || rejected >= 0 ||
        chmod(cache, 0700) < 0) goto done;
    if (setenv("XDG_CACHE_HOME", cache, 1) < 0 ||
        tm_local_store_open_default(&default_fd) < 0 ||
        fstat(default_fd, &second_status) < 0 ||
        first_status.st_ino != second_status.st_ino ||
        first_status.st_dev != second_status.st_dev) goto done;
    close(default_fd); default_fd = -1;
    if (snprintf(new_xdg, sizeof(new_xdg), "%s/new-xdg", cache) >=
            (int)sizeof(new_xdg) ||
        setenv("XDG_CACHE_HOME", new_xdg, 1) < 0 ||
        tm_local_store_open_default(&default_fd) < 0 || default_fd < 0 ||
        stat(new_xdg, &second_status) < 0 ||
        !S_ISDIR(second_status.st_mode) || second_status.st_uid != getuid() ||
        (second_status.st_mode & 077) != 0) goto done;
    close(default_fd); default_fd = -1;
    if (setenv("XDG_CACHE_HOME", "relative-cache", 1) < 0 ||
        tm_local_store_open_default(&rejected) == 0 || rejected >= 0)
        goto done;
    if (snprintf(app_path, sizeof(app_path), "%s/testmiser", cache) >=
            (int)sizeof(app_path) ||
        snprintf(store_path, sizeof(store_path), "%s/testmiser/store", cache) >=
            (int)sizeof(store_path)) goto done;
    if (chmod(store_path, 0755) < 0 ||
        tm_local_store_open(cache, &rejected) == 0 || rejected >= 0 ||
        chmod(store_path, 0700) < 0) goto done;
    {
        char link_path[256];
        if (snprintf(link_path, sizeof(link_path), "%s/testmiser", hostile) >=
            (int)sizeof(link_path) || symlink(app_path, link_path) < 0 ||
            tm_local_store_open(hostile, &rejected) == 0 || rejected >= 0)
            goto done;
    }
    if (snprintf(store_link_path, sizeof(store_link_path), "%s/store-link",
                 hostile) >= (int)sizeof(store_link_path) ||
        symlink(cache, store_link_path) < 0 ||
        setenv("TM_SHARED_STORE", store_link_path, 1) < 0 ||
        tm_shared_store_open_configured(&rejected) == 0 || rejected >= 0 ||
        tm_local_store_open(store_link_path, &rejected) == 0 ||
        rejected >= 0 ||
        setenv("XDG_CACHE_HOME", store_link_path, 1) < 0 ||
        tm_local_store_open_default(&rejected) == 0 || rejected >= 0 ||
        setenv("TM_SHARED_STORE", "/tmp/../tmp", 1) < 0 ||
        tm_shared_store_open_configured(&rejected) == 0 || rejected >= 0)
        goto done;
    if (mkdtemp(home) == NULL || setenv("HOME", home, 1) < 0 ||
        unsetenv("XDG_CACHE_HOME") < 0 ||
        tm_local_store_open_default(&default_fd) < 0 || default_fd < 0)
        goto done;
    status = 0;

done:
    if (first >= 0) close(first);
    if (second >= 0) close(second);
    if (default_fd >= 0) close(default_fd);
    if (shared_fd >= 0) close(shared_fd);
    if (rejected >= 0) close(rejected);
    if (saved_xdg != NULL) (void)setenv("XDG_CACHE_HOME", saved_xdg, 1);
    else if (!had_xdg) (void)unsetenv("XDG_CACHE_HOME");
    if (saved_home != NULL) (void)setenv("HOME", saved_home, 1);
    else if (!had_home) (void)unsetenv("HOME");
    if (saved_shared != NULL) (void)setenv("TM_SHARED_STORE", saved_shared, 1);
    else if (!had_shared) (void)unsetenv("TM_SHARED_STORE");
    if (status != 0) fprintf(stderr, "local store test failed: %s\n", strerror(errno));
    if (cache[0] != '\0') {
        if (new_xdg[0] != '\0') {
            snprintf(store_path, sizeof(store_path),
                     "%s/testmiser/store", new_xdg);
            rmdir(store_path);
            snprintf(store_path, sizeof(store_path), "%s/testmiser", new_xdg);
            rmdir(store_path);
            rmdir(new_xdg);
        }
        snprintf(store_path, sizeof(store_path), "%s/testmiser/store", cache);
        rmdir(store_path);
        snprintf(store_path, sizeof(store_path), "%s/testmiser", cache);
        rmdir(store_path);
        rmdir(cache);
    }
    if (hostile[0] != '\0') {
        snprintf(store_path, sizeof(store_path), "%s/store-link", hostile);
        unlink(store_path);
        snprintf(app_path, sizeof(app_path), "%s/testmiser", hostile);
        unlink(app_path);
        rmdir(hostile);
    }
    if (home[0] != '\0') {
        snprintf(store_path, sizeof(store_path), "%s/.cache/testmiser/store", home);
        rmdir(store_path);
        snprintf(store_path, sizeof(store_path), "%s/.cache/testmiser", home);
        rmdir(store_path);
        snprintf(store_path, sizeof(store_path), "%s/.cache", home);
        rmdir(store_path);
        rmdir(home);
    }
    free(saved_xdg);
    free(saved_home);
    free(saved_shared);
    return status;
}
