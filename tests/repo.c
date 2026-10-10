#define _XOPEN_SOURCE 700

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/repo.h"

int main(void)
{
    char git_root[] = "/tmp/tm-repo-git-XXXXXX";
    char git_worktree[] = "/tmp/tm-repo-file-XXXXXX";
    char fallback[] = "/tmp/tm-repo-fallback-XXXXXX";
    char git_path[256] = {0}, nested_path[256] = {0};
    char worktree_path[256] = {0}, worktree_subdir[256] = {0};
    char fallback_child[256] = {0};
    char original[4096] = {0};
    char *resolved = NULL, *relative = NULL;
    int marker_fd = -1, status = 1, stage = 1;

    if (getcwd(original, sizeof(original)) == NULL ||
        mkdtemp(git_root) == NULL || mkdtemp(git_worktree) == NULL ||
        mkdtemp(fallback) == NULL) goto done;
    snprintf(git_path, sizeof(git_path), "%s/.git", git_root);
    snprintf(nested_path, sizeof(nested_path), "%s/subdir", git_root);
    if (mkdir(git_path, 0700) < 0 || mkdir(nested_path, 0700) < 0 ||
        chdir(nested_path) < 0 || tm_repo_root(NULL, &resolved) < 0 ||
        strcmp(resolved, git_root) != 0) goto done;
    stage = 2;
    relative = tm_repo_relative_path(resolved, "/unrelated/path");
    if (relative != NULL || errno != EXDEV) goto done;
    relative = tm_repo_relative_path(resolved, git_root);
    if (relative == NULL || strcmp(relative, ".") != 0) goto done;
    free(relative); relative = NULL;
    {
        char inside[512];
        snprintf(inside, sizeof(inside), "%s/subdir/file.c", git_root);
        relative = tm_repo_relative_path(resolved, inside);
        if (relative == NULL || strcmp(relative, "subdir/file.c") != 0)
            goto done;
        free(relative); relative = NULL;
        snprintf(inside, sizeof(inside), "%s/./subdir/./file.c", git_root);
        relative = tm_repo_relative_path(resolved, inside);
        if (relative == NULL || strcmp(relative, "subdir/file.c") != 0)
            goto done;
    }
    free(relative); relative = NULL;
    free(resolved); resolved = NULL;

    stage = 3;
    snprintf(worktree_path, sizeof(worktree_path), "%s/.git", git_worktree);
    snprintf(worktree_subdir, sizeof(worktree_subdir), "%s/child", git_worktree);
    marker_fd = open(worktree_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker_fd < 0) goto done;
    {
        int fd = marker_fd;
        marker_fd = -1;
        if (close(fd) < 0) goto done;
    }
    if (mkdir(worktree_subdir, 0700) < 0 || chdir(worktree_subdir) < 0 ||
        tm_repo_root(NULL, &resolved) < 0 || strcmp(resolved, git_worktree) != 0)
        goto done;
    free(resolved); resolved = NULL;

    stage = 4;
    stage = 5;
    snprintf(fallback_child, sizeof(fallback_child), "%s/child", fallback);
    if (mkdir(fallback_child, 0700) < 0) goto done;
    if (chdir(fallback_child) < 0 || tm_repo_root(NULL, &resolved) < 0)
        goto done;
    {
        struct stat marker_status;
        const char *expected = lstat("/tmp/.git", &marker_status) == 0 ? "/tmp" :
                               fallback_child;
        if (strcmp(resolved, expected) != 0) goto done;
    }
    free(resolved); resolved = NULL;
    stage = 6;
    if (tm_repo_root(fallback, &resolved) < 0 || strcmp(resolved, fallback) != 0)
        goto done;
    status = 0;
done:
    if (status != 0)
        fprintf(stderr, "repository root test failed at stage %d: %s\n",
                stage, strerror(errno));
    if (marker_fd >= 0) close(marker_fd);
    free(relative);
    free(resolved);
    if (original[0] != '\0' && chdir(original) < 0) {
        fprintf(stderr, "could not restore test working directory: %s\n",
                strerror(errno));
        status = 1;
    }
    if (worktree_path[0] != '\0') unlink(worktree_path);
    if (worktree_subdir[0] != '\0') rmdir(worktree_subdir);
    if (fallback_child[0] != '\0') rmdir(fallback_child);
    if (git_path[0] != '\0') rmdir(git_path);
    if (nested_path[0] != '\0') rmdir(nested_path);
    if (git_root[0] != '\0') rmdir(git_root);
    if (git_worktree[0] != '\0') rmdir(git_worktree);
    if (fallback[0] != '\0') rmdir(fallback);
    return status;
}
