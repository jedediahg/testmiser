#define _XOPEN_SOURCE 700

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "tm/repo.h"

static int is_repository_marker(const char *directory)
{
    char marker[PATH_MAX];
    struct stat status;
    int length = snprintf(marker, sizeof(marker), "%s/.git", directory);
    return length > 0 && (size_t)length < sizeof(marker) &&
           lstat(marker, &status) == 0 &&
           (S_ISDIR(status.st_mode) || S_ISREG(status.st_mode));
}

int tm_repo_root(const char *requested, char **output)
{
    char *current;
    char *fallback;
    struct stat status;

    if (output == NULL) { errno = EINVAL; return -1; }
    *output = NULL;
    if (requested != NULL) {
        current = realpath(requested, NULL);
        if (current == NULL) return -1;
        if (stat(current, &status) < 0) {
            int saved = errno;
            free(current);
            errno = saved;
            return -1;
        }
        if (!S_ISDIR(status.st_mode)) {
            free(current);
            errno = ENOTDIR;
            return -1;
        }
        *output = current;
        return 0;
    }

    current = realpath(".", NULL);
    if (current == NULL) return -1;
    fallback = strdup(current);
    if (fallback == NULL) { free(current); return -1; }
    for (;;) {
        char *slash;
        if (is_repository_marker(current)) {
            free(fallback);
            *output = current;
            return 0;
        }
        if (strcmp(current, "/") == 0) {
            free(current);
            *output = fallback;
            return 0;
        }
        slash = strrchr(current, '/');
        if (slash == NULL) {
            free(current);
            free(fallback);
            errno = EINVAL;
            return -1;
        }
        if (slash == current) current[1] = '\0';
        else *slash = '\0';
    }
}

static char *normalize_relative_path(const char *path)
{
    size_t length = strlen(path), input = 0, output = 0;
    char *normalized = malloc(length + 1);
    if (normalized == NULL) return NULL;
    while (input < length) {
        size_t start, component_length;
        while (input < length && path[input] == '/') input++;
        start = input;
        while (input < length && path[input] != '/') input++;
        component_length = input - start;
        if (component_length == 0 ||
            (component_length == 1 && path[start] == '.')) continue;
        if (output != 0) normalized[output++] = '/';
        memcpy(normalized + output, path + start, component_length);
        output += component_length;
    }
    if (output == 0) normalized[output++] = '.';
    normalized[output] = '\0';
    return normalized;
}

char *tm_repo_relative_path(const char *root, const char *absolute_path)
{
    size_t root_length;
    const char *relative;
    if (root == NULL || absolute_path == NULL || absolute_path[0] != '/') {
        errno = EXDEV;
        return NULL;
    }
    root_length = strlen(root);
    if (strcmp(root, absolute_path) == 0) return strdup(".");
    if (root_length == 1 && root[0] == '/')
        return normalize_relative_path(absolute_path + 1);
    if (strlen(absolute_path) < root_length ||
        strncmp(root, absolute_path, root_length) != 0 ||
        (absolute_path[root_length] != '\0' &&
         absolute_path[root_length] != '/')) {
        errno = EXDEV;
        return NULL;
    }
    if (absolute_path[root_length] == '\0') return strdup(".");
    relative = absolute_path + root_length + 1;
    return normalize_relative_path(relative);
}
