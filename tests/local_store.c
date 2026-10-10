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
    char app_path[256], store_path[256];
    struct stat first_status, second_status;
    int first = -1, second = -1, rejected = -1, status = 1;

    if (mkdtemp(cache) == NULL || mkdtemp(hostile) == NULL ||
        tm_local_store_open(cache, &first) < 0 ||
        tm_local_store_open(cache, &second) < 0 ||
        fstat(first, &first_status) < 0 || fstat(second, &second_status) < 0 ||
        first_status.st_ino != second_status.st_ino ||
        first_status.st_dev != second_status.st_dev ||
        (first_status.st_mode & 077) != 0 || first_status.st_uid != getuid())
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
    status = 0;

done:
    if (first >= 0) close(first);
    if (second >= 0) close(second);
    if (rejected >= 0) close(rejected);
    if (status != 0) fprintf(stderr, "local store test failed: %s\n", strerror(errno));
    if (cache[0] != '\0') {
        snprintf(store_path, sizeof(store_path), "%s/testmiser/store", cache);
        rmdir(store_path);
        snprintf(store_path, sizeof(store_path), "%s/testmiser", cache);
        rmdir(store_path);
        rmdir(cache);
    }
    if (hostile[0] != '\0') {
        snprintf(app_path, sizeof(app_path), "%s/testmiser", hostile);
        unlink(app_path);
        rmdir(hostile);
    }
    return status;
}
