#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "tm/lock.h"
#include "tm/local_store.h"

static const char *profile_digest =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
static const char *context_digest =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
static const char *command_digest =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
static const char *other_command_digest =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";

static int count_files(const char *directory_path)
{
    DIR *directory = opendir(directory_path);
    struct dirent *entry;
    int count = 0;
    if (directory == NULL) return -1;
    while ((entry = readdir(directory)) != NULL)
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0) count++;
    closedir(directory);
    return count;
}

int main(void)
{
    char cache[] = "/tmp/tm-lock-test-XXXXXX";
    char link[] = "/tmp/tm-lock-link-XXXXXX";
    char lock_directory[256] = {0}, unsafe_root[512];
    struct tm_lock held = {-1}, independent = {-1}, rejected = {-1};
    struct tm_lock shared_held = {-1};
    int ready[2] = {-1, -1}, acquired[2] = {-1, -1};
    int shared_ready[2] = {-1, -1}, shared_acquired[2] = {-1, -1};
    int store_fd = -1;
    pid_t child = -1;
    char *old_xdg_cache = NULL;
    int had_xdg_cache = 0;
    char *old_shared_store = NULL;
    int had_shared_store = 0;
    int status = 1, stage = 1;

    if (mkdtemp(cache) == NULL ||
        tm_lock_acquire(cache, "sample", command_digest, profile_digest,
                        context_digest, &held) < 0 ||
        tm_lock_acquire(cache, "sample", other_command_digest, profile_digest,
                        context_digest, &independent) < 0) goto done;
    stage = 2;
    tm_lock_release(&independent);
    if (snprintf(lock_directory, sizeof(lock_directory),
                 "%s/testmiser/locks", cache) >= (int)sizeof(lock_directory) ||
        count_files(lock_directory) != 2 || pipe(ready) < 0 ||
        pipe(acquired) < 0) goto done;
    {
        const char *current = getenv("XDG_CACHE_HOME");
        if (current != NULL) {
            old_xdg_cache = strdup(current);
            if (old_xdg_cache == NULL) goto done;
            had_xdg_cache = 1;
        }
        if (setenv("XDG_CACHE_HOME", cache, 1) < 0) goto done;
        current = getenv("TM_SHARED_STORE");
        if (current != NULL) {
            old_shared_store = strdup(current);
            if (old_shared_store == NULL) goto done;
            had_shared_store = 1;
        }
    }
    stage = 3;
    child = fork();
    if (child < 0) goto done;
    stage = 4;
    if (child == 0) {
        struct tm_lock second = {-1};
        char byte = 'r';
        close(held.fd);
        close(ready[0]);
        close(acquired[0]);
        if (write(ready[1], &byte, 1) != 1) _exit(2);
        if (tm_lock_acquire_default("sample", command_digest, profile_digest,
                                    context_digest, &second) < 0) {
            perror("child lock acquire");
            _exit(2);
        }
        byte = 'a';
        if (write(acquired[1], &byte, 1) != 1) _exit(2);
        tm_lock_release(&second);
        _exit(0);
    }
    close(ready[1]); ready[1] = -1;
    close(acquired[1]); acquired[1] = -1;
    stage = 5;
    {
        char byte;
        struct pollfd event = {acquired[0], POLLIN, 0};
        int polled;
        if (read(ready[0], &byte, 1) != 1 || byte != 'r') goto done;
        polled = poll(&event, 1, 100);
        if (polled != 0) {
            fprintf(stderr, "lock became available early: poll=%d revents=%d\n",
                    polled, event.revents);
            goto done;
        }
        tm_lock_release(&held);
        polled = poll(&event, 1, 5000);
        if (polled != 1 || read(acquired[0], &byte, 1) != 1 || byte != 'a') {
            fprintf(stderr, "lock did not release: poll=%d revents=%d\n",
                    polled, event.revents);
            goto done;
        }
    }
    {
        int child_status;
        if (waitpid(child, &child_status, 0) != child ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
            goto done;
        child = -1;
    }
    stage = 6;
    if (mkdtemp(link) == NULL) goto done;
    if (rmdir(link) < 0 || symlink(cache, link) < 0 ||
        tm_lock_acquire(link, "sample", command_digest, profile_digest,
                        context_digest, &rejected) == 0 || rejected.fd >= 0)
        goto done;
    if (unlink(link) < 0 || symlink("/tmp", link) < 0 ||
        snprintf(unsafe_root, sizeof(unsafe_root), "%s/%s", link,
                 cache + strlen("/tmp/")) >= (int)sizeof(unsafe_root) ||
        tm_lock_acquire(unsafe_root, "sample", command_digest,
                        profile_digest, context_digest, &rejected) == 0 ||
        rejected.fd >= 0 ||
        snprintf(unsafe_root, sizeof(unsafe_root), "%s/../%s", cache,
                 cache + strlen("/tmp/")) >= (int)sizeof(unsafe_root) ||
        tm_lock_acquire(unsafe_root, "sample", command_digest,
                        profile_digest, context_digest, &rejected) == 0 ||
        rejected.fd >= 0)
        goto done;
    if (tm_lock_acquire(cache, "Bad Repo", command_digest, profile_digest,
                        context_digest, &rejected) == 0) goto done;
    stage = 7;
    if (setenv("TM_SHARED_STORE", cache, 1) < 0 ||
        tm_shared_store_open_configured(&store_fd) != 0 ||
        tm_lock_acquire_store(store_fd, "sample", command_digest,
            profile_digest, context_digest, &shared_held) < 0 ||
        pipe(shared_ready) < 0 || pipe(shared_acquired) < 0) goto done;
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        struct tm_lock second = {-1};
        char byte = 'r';
        close(shared_held.fd);
        close(shared_ready[0]);
        close(shared_acquired[0]);
        if (write(shared_ready[1], &byte, 1) != 1) _exit(2);
        if (tm_lock_acquire_store(store_fd, "sample", command_digest,
                profile_digest, context_digest, &second) < 0) _exit(2);
        byte = 'a';
        if (write(shared_acquired[1], &byte, 1) != 1) _exit(2);
        tm_lock_release(&second);
        _exit(0);
    }
    close(shared_ready[1]); shared_ready[1] = -1;
    close(shared_acquired[1]); shared_acquired[1] = -1;
    {
        char byte;
        struct pollfd event = {shared_acquired[0], POLLIN, 0};
        int polled;
        if (read(shared_ready[0], &byte, 1) != 1 || byte != 'r') goto done;
        polled = poll(&event, 1, 100);
        if (polled != 0) {
            fprintf(stderr, "shared-store lock became available early\n");
            goto done;
        }
        tm_lock_release(&shared_held);
        polled = poll(&event, 1, 5000);
        if (polled != 1 || read(shared_acquired[0], &byte, 1) != 1 ||
            byte != 'a') {
            fprintf(stderr, "shared-store lock did not release\n");
            goto done;
        }
    }
    {
        int child_status;
        if (waitpid(child, &child_status, 0) != child ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
            goto done;
        child = -1;
    }
    stage = 8;
    status = 0;

done:
    if (had_xdg_cache) (void)setenv("XDG_CACHE_HOME", old_xdg_cache, 1);
    else (void)unsetenv("XDG_CACHE_HOME");
    free(old_xdg_cache);
    if (had_shared_store) (void)setenv("TM_SHARED_STORE", old_shared_store, 1);
    else (void)unsetenv("TM_SHARED_STORE");
    free(old_shared_store);
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
    if (ready[0] >= 0) close(ready[0]);
    if (ready[1] >= 0) close(ready[1]);
    if (acquired[0] >= 0) close(acquired[0]);
    if (acquired[1] >= 0) close(acquired[1]);
    if (shared_ready[0] >= 0) close(shared_ready[0]);
    if (shared_ready[1] >= 0) close(shared_ready[1]);
    if (shared_acquired[0] >= 0) close(shared_acquired[0]);
    if (shared_acquired[1] >= 0) close(shared_acquired[1]);
    tm_lock_release(&held);
    tm_lock_release(&independent);
    tm_lock_release(&rejected);
    tm_lock_release(&shared_held);
    if (store_fd >= 0) close(store_fd);
    if (link[0] != '\0') unlink(link);
    if (cache[0] != '\0') {
        DIR *directory;
        struct dirent *entry;
        if (lock_directory[0] != '\0' &&
            (directory = opendir(lock_directory)) != NULL) {
            while ((entry = readdir(directory)) != NULL) {
                char file[320];
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) continue;
                if (snprintf(file, sizeof(file), "%s/%s", lock_directory,
                             entry->d_name) < (int)sizeof(file)) unlink(file);
            }
            closedir(directory);
        }
        snprintf(lock_directory, sizeof(lock_directory), "%s/testmiser/locks", cache);
        rmdir(lock_directory);
        snprintf(lock_directory, sizeof(lock_directory), "%s/testmiser/store/locks", cache);
        if ((directory = opendir(lock_directory)) != NULL) {
            while ((entry = readdir(directory)) != NULL) {
                char file[320];
                if (strcmp(entry->d_name, ".") == 0 ||
                    strcmp(entry->d_name, "..") == 0) continue;
                if (snprintf(file, sizeof(file), "%s/%s", lock_directory,
                             entry->d_name) < (int)sizeof(file)) unlink(file);
            }
            closedir(directory);
        }
        rmdir(lock_directory);
        snprintf(lock_directory, sizeof(lock_directory), "%s/testmiser/store", cache);
        rmdir(lock_directory);
        snprintf(lock_directory, sizeof(lock_directory), "%s/testmiser", cache);
        rmdir(lock_directory);
        rmdir(cache);
    }
    if (status != 0)
        fprintf(stderr, "local lock test failed at stage %d: %s\n",
                stage, strerror(errno));
    return status;
}
