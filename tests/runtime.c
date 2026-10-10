#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/runtime.h"

static int write_file(const char *path, const char *content, mode_t mode)
{
    size_t length = strlen(content), offset = 0;
    int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (descriptor < 0) return -1;
    while (offset < length) {
        ssize_t amount = write(descriptor, content + offset, length - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) { close(descriptor); return -1; }
        offset += (size_t)amount;
    }
    return close(descriptor);
}

static int make_tree(const char *root, int reverse)
{
    char bin[512], alpha[512], lib[512], runtime_file[512], alias[512];
#define PATH(dst, suffix) \
    do { if (snprintf((dst), sizeof(dst), "%s/%s", root, suffix) >= \
             (int)sizeof(dst)) return -1; } while (0)
    PATH(bin, "bin");
    PATH(alpha, "bin/alpha");
    PATH(lib, "lib");
    PATH(runtime_file, "lib/z-runtime");
    PATH(alias, "lib/alias");
    if (reverse) {
        if (mkdir(lib, 0755) < 0 ||
            write_file(runtime_file, "library\n", 0644) < 0 ||
            symlink("../bin/alpha", alias) < 0 || mkdir(bin, 0755) < 0 ||
            write_file(alpha, "runtime\n", 0755) < 0) return -1;
    } else {
        if (mkdir(bin, 0755) < 0 || write_file(alpha, "runtime\n", 0755) < 0 ||
            mkdir(lib, 0755) < 0 ||
            write_file(runtime_file, "library\n", 0644) < 0 ||
            symlink("../bin/alpha", alias) < 0) return -1;
    }
#undef PATH
    return 0;
}

int main(void)
{
    char first[] = "/tmp/tm-runtime-first-XXXXXX";
    char second[] = "/tmp/tm-runtime-second-XXXXXX";
    char digest_a[72], digest_b[72];
    char alpha[512], alias[512], fifo[512], added[512];
    int status = 1, root_descriptor = -1;
    if (mkdtemp(first) == NULL || mkdtemp(second) == NULL ||
        make_tree(first, 0) < 0 || make_tree(second, 1) < 0 ||
        tm_runtime_tree_digest(first, digest_a) < 0 ||
        tm_runtime_tree_digest(second, digest_b) < 0 ||
        strlen(digest_a) != 71 || strncmp(digest_a, "sha256:", 7) != 0 ||
        strcmp(digest_a, digest_b) != 0) {
        fprintf(stderr, "runtime tree digest was not creation-order stable: %s\n",
                strerror(errno));
        goto done;
    }
    root_descriptor = open(second, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_descriptor < 0 ||
        tm_runtime_tree_digest_fd(root_descriptor, digest_b) < 0 ||
        strcmp(digest_a, digest_b) != 0) {
        fprintf(stderr, "runtime descriptor digest differed from path digest\n");
        goto done;
    }
    errno = 0;
    if (tm_runtime_tree_digest_readonly_fd(root_descriptor, NULL, 0,
                                           digest_b) == 0 || errno != EROFS) {
        fprintf(stderr, "runtime tree owned by the caller passed read-only gate\n");
        goto done;
    }
    printf("%s\n", digest_a);
    snprintf(alpha, sizeof(alpha), "%s/bin/alpha", second);
    snprintf(alias, sizeof(alias), "%s/lib/alias", second);
    snprintf(fifo, sizeof(fifo), "%s/fifo", second);
    snprintf(added, sizeof(added), "%s/new-entry", second);
    if (chmod(alpha, 0700) < 0 || tm_runtime_tree_digest(second, digest_b) < 0 ||
        strcmp(digest_a, digest_b) == 0 || chmod(alpha, 0755) < 0 ||
        unlink(alpha) < 0 || write_file(alpha, "changed\n", 0755) < 0 ||
        tm_runtime_tree_digest(second, digest_b) < 0 ||
        strcmp(digest_a, digest_b) == 0 || unlink(alpha) < 0 ||
        write_file(alpha, "runtime\n", 0755) < 0 ||
        unlink(alias) < 0 || symlink("../bin/other", alias) < 0 ||
        tm_runtime_tree_digest(second, digest_b) < 0 ||
        strcmp(digest_a, digest_b) == 0 || unlink(alias) < 0 ||
        symlink("../bin/alpha", alias) < 0 ||
        write_file(added, "new\n", 0644) < 0 ||
        tm_runtime_tree_digest(second, digest_b) < 0 ||
        strcmp(digest_a, digest_b) == 0 || unlink(added) < 0 ||
        mkfifo(fifo, 0600) < 0 || tm_runtime_tree_digest(second, digest_b) == 0)
        goto done;
    status = 0;
done:
    if (root_descriptor >= 0) close(root_descriptor);
    snprintf(alpha, sizeof(alpha), "%s/bin/alpha", first); unlink(alpha);
    snprintf(alpha, sizeof(alpha), "%s/lib/alias", first); unlink(alpha);
    snprintf(alpha, sizeof(alpha), "%s/lib/z-runtime", first); unlink(alpha);
    snprintf(alpha, sizeof(alpha), "%s/bin", first); rmdir(alpha);
    snprintf(alpha, sizeof(alpha), "%s/lib", first); rmdir(alpha);
    rmdir(first);
    snprintf(alpha, sizeof(alpha), "%s/bin/alpha", second); unlink(alpha);
    snprintf(alpha, sizeof(alpha), "%s/lib/alias", second); unlink(alpha);
    snprintf(alpha, sizeof(alpha), "%s/lib/z-runtime", second); unlink(alpha);
    snprintf(alpha, sizeof(alpha), "%s/bin", second); rmdir(alpha);
    snprintf(alpha, sizeof(alpha), "%s/lib", second); rmdir(alpha);
    snprintf(fifo, sizeof(fifo), "%s/fifo", second); unlink(fifo);
    rmdir(second);
    return status;
}
