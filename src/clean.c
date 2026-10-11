#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/clean.h"
#include "tm/lock.h"
#include "tm/repo.h"
#include "tm/tm.h"

static int is_record_name(const char *name)
{
    size_t length = strlen(name);
    return length >= 8 && strcmp(name + length - 8, ".tm.json") == 0;
}

static int remove_records(int directory_fd)
{
    DIR *directory;
    struct dirent *entry;
    int scan_fd = dup(directory_fd);
    int result = 0;

    if (scan_fd < 0) return -1;
    directory = fdopendir(scan_fd);
    if (directory == NULL) {
        close(scan_fd);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat status;
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (fstatat(directory_fd, entry->d_name, &status,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            result = -1;
            break;
        }
        if (S_ISDIR(status.st_mode)) {
            int child_fd = openat(directory_fd, entry->d_name,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                  O_NOFOLLOW);
            if (child_fd < 0 || remove_records(child_fd) < 0) {
                if (child_fd >= 0) close(child_fd);
                result = -1;
                break;
            }
            close(child_fd);
        } else if (S_ISREG(status.st_mode) && is_record_name(entry->d_name) &&
                   unlinkat(directory_fd, entry->d_name, 0) < 0) {
            result = -1;
            break;
        }
        errno = 0;
    }
    if (entry == NULL && errno != 0) result = -1;
    closedir(directory);
    return result;
}

int tm_clean_main(int argc, char **argv)
{
    const char *requested_root = NULL;
    char *root = NULL;
    int records = 0, root_fd = -1, tm_fd = -1, results_fd = -1;
    struct tm_lock publication_lock = {-1};
    int index, result = TM_EXIT_INTERNAL_ERROR;

    for (index = 2; index < argc; index++) {
        if (strcmp(argv[index], "--records") == 0) {
            records = 1;
        } else if (strcmp(argv[index], "--root") == 0 &&
                   requested_root == NULL && index + 1 < argc) {
            requested_root = argv[++index];
        } else {
            fprintf(stderr, "Usage: tm clean [--root DIR] [--records]\n");
            return TM_EXIT_INTERNAL_ERROR;
        }
    }
    if (!records) return 0;
    if (tm_repo_root(requested_root, &root) < 0) goto failure;
    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) goto failure;
    tm_fd = openat(root_fd, ".tm", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                   O_NOFOLLOW);
    if (tm_fd < 0 && errno == ENOENT) { result = 0; goto done; }
    if (tm_fd < 0) goto failure;
    if (tm_lock_acquire_repository_results(root_fd, &publication_lock) < 0)
        goto failure;
    results_fd = openat(tm_fd, "results", O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                        O_NOFOLLOW);
    if (results_fd < 0 && errno == ENOENT) { result = 0; goto done; }
    if (results_fd < 0) goto failure;
    if (remove_records(results_fd) < 0) goto failure;
    result = 0;
    goto done;

failure:
    fprintf(stderr, "tm: clean failed: %s\n", strerror(errno));
done:
    tm_lock_release(&publication_lock);
    if (results_fd >= 0) close(results_fd);
    if (tm_fd >= 0) close(tm_fd);
    if (root_fd >= 0) close(root_fd);
    free(root);
    return result;
}
