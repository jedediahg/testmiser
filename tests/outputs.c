#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/outputs.h"

static int write_file(int directory, const char *name, const char *data)
{
    size_t length = strlen(data), offset = 0;
    int fd = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    0600);
    if (fd < 0) return -1;
    while (offset < length) {
        ssize_t n = write(fd, data + offset, length - offset);
        if (n < 0) { close(fd); return -1; }
        offset += (size_t)n;
    }
    if (fchmod(fd, 0640) < 0) { close(fd); return -1; }
    return close(fd);
}

int main(void)
{
    static const char digest[] =
        "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    char root[] = "/tmp/tm-output-capture-XXXXXX";
    char blob_path[512];
    const char *roots[] = {"build/reports"};
    const char *overlap[] = {"build", "build/reports"};
    const char *single_root[] = {"artifact.txt"};
    struct tm_output_manifest manifest = {0};
    int root_fd = -1, build_fd = -1, reports_fd = -1, sub_fd = -1;
    int file_fd = -1, status = 1;
    char bytes[6] = {0};
    if (mkdtemp(root) == NULL) goto done;
    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0 || mkdirat(root_fd, "build", 0700) < 0) goto done;
    build_fd = openat(root_fd, "build", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (build_fd < 0 || mkdirat(build_fd, "reports", 0700) < 0) goto done;
    reports_fd = openat(build_fd, "reports",
                        O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (reports_fd < 0 || mkdirat(reports_fd, "sub", 0700) < 0 ||
        write_file(reports_fd, "a.txt", "hello") < 0) goto done;
    sub_fd = openat(reports_fd, "sub", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (sub_fd < 0 || write_file(sub_fd, "b.txt", "hello") < 0) goto done;

    if (tm_outputs_capture(root_fd, roots, 1, &manifest) < 0 ||
        manifest.count != 4 ||
        strcmp(manifest.entries[0].path, "build/reports") != 0 ||
        manifest.entries[0].kind != TM_OUTPUT_DIRECTORY ||
        strcmp(manifest.entries[1].path, "build/reports/a.txt") != 0 ||
        manifest.entries[1].kind != TM_OUTPUT_FILE ||
        strcmp(manifest.entries[1].digest, digest) != 0 ||
        manifest.entries[1].size != 5 || manifest.entries[1].mode != 0640 ||
        strcmp(manifest.entries[2].path, "build/reports/sub") != 0 ||
        strcmp(manifest.entries[3].path, "build/reports/sub/b.txt") != 0 ||
        strcmp(manifest.entries[3].digest, digest) != 0) goto done;

    if (tm_outputs_verify_store(root_fd, &manifest) < 0) goto done;

    snprintf(blob_path, sizeof(blob_path), "%s/.tm/blobs/sha256/%s", root,
             digest + 7);
    if (chmod(blob_path, 0644) < 0) goto done;
    file_fd = open(blob_path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file_fd < 0 || pwrite(file_fd, "jello", 5, 0) != 5 ||
        close(file_fd) < 0) goto done;
    file_fd = -1;
    if (chmod(blob_path, 0444) < 0 ||
        tm_outputs_verify_store(root_fd, &manifest) == 0 ||
        unlink(blob_path) < 0 ||
        tm_outputs_capture(root_fd, roots, 1, &manifest) < 0 ||
        tm_outputs_verify_store(root_fd, &manifest) < 0) goto done;
    file_fd = open(blob_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (file_fd < 0 || read(file_fd, bytes, 5) != 5 ||
        memcmp(bytes, "hello", 5) != 0) goto done;
    close(file_fd); file_fd = -1;

    if (write_file(reports_fd, "stale.txt", "stale") < 0) goto done;
    close(sub_fd); sub_fd = -1;
    close(reports_fd); reports_fd = -1;
    {
        char original = manifest.entries[1].digest[7];
        manifest.entries[1].digest[7] = original == '0' ? '1' : '0';
        if (tm_outputs_restore(root_fd, roots, 1, &manifest) == 0) goto done;
        manifest.entries[1].digest[7] = original;
        reports_fd = openat(build_fd, "reports", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (reports_fd < 0 ||
            fstatat(reports_fd, "stale.txt", &(struct stat){0}, AT_SYMLINK_NOFOLLOW) < 0)
            goto done;
        close(reports_fd); reports_fd = -1;
    }
    {
        char collision[101][80];
        size_t i;
        for (i = 0; i < 101; i++) {
            snprintf(collision[i], sizeof(collision[i]), ".tm-restore-%ld-%zu",
                     (long)getpid(), i);
            if (mkdirat(build_fd, collision[i], 0700) < 0) goto done;
        }
        if (tm_outputs_restore(root_fd, roots, 1, &manifest) == 0) {
            fprintf(stderr, "restore ignored a staging collision\n"); goto done;
        }
        for (i = 0; i < 101; i++) {
            if (fstatat(build_fd, collision[i], &(struct stat){0}, AT_SYMLINK_NOFOLLOW) < 0 ||
                unlinkat(build_fd, collision[i], AT_REMOVEDIR) < 0) {
                perror("restore removed unowned staging collision"); goto done;
            }
        }
    }
    if (tm_outputs_restore(root_fd, roots, 1, &manifest) < 0) {
        perror("tm_outputs_restore"); goto done;
    }
    reports_fd = openat(build_fd, "reports", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (reports_fd < 0) { perror("reopen reports"); goto done; }
    if (fstatat(reports_fd, "stale.txt", &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0) {
        fprintf(stderr, "stale output remained after restore\n"); goto done;
    }
    if (errno != ENOENT) { perror("check stale output"); goto done; }
    sub_fd = openat(reports_fd, "sub", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (sub_fd < 0) { perror("open restored subdirectory"); goto done; }
    file_fd = openat(sub_fd, "b.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    memset(bytes, 0, sizeof(bytes));
    if (file_fd < 0) { perror("open restored file"); goto done; }
    if (read(file_fd, bytes, 5) != 5 || memcmp(bytes, "hello", 5) != 0) goto done;
    close(file_fd); file_fd = -1;
    close(sub_fd); sub_fd = -1;

    sub_fd = openat(reports_fd, "sub", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (sub_fd < 0) goto done;
    if (symlinkat("/etc/passwd", sub_fd, "link") < 0) goto done;
    if (tm_outputs_capture(root_fd, roots, 1, &manifest) == 0 ||
        manifest.entries != NULL || manifest.count != 0) goto done;
    if (unlinkat(sub_fd, "link", 0) < 0 ||
        tm_outputs_capture(root_fd, overlap, 2, &manifest) == 0 ||
        manifest.entries != NULL || manifest.count != 0) goto done;
    if (write_file(root_fd, "artifact.txt", "hello") < 0 ||
        tm_outputs_capture(root_fd, single_root, 1, &manifest) < 0 ||
        manifest.count != 1 || manifest.entries[0].kind != TM_OUTPUT_FILE ||
        unlinkat(root_fd, "artifact.txt", 0) < 0 ||
        tm_outputs_restore(root_fd, single_root, 1, &manifest) < 0) goto done;
    file_fd = openat(root_fd, "artifact.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    memset(bytes, 0, sizeof(bytes));
    if (file_fd < 0 || read(file_fd, bytes, 5) != 5 ||
        memcmp(bytes, "hello", 5) != 0) goto done;
    close(file_fd); file_fd = -1;
    status = 0;
done:
    if (status != 0) perror("output capture test");
    if (file_fd >= 0) close(file_fd);
    tm_output_manifest_clear(&manifest);
    if (sub_fd >= 0) close(sub_fd);
    if (reports_fd >= 0) close(reports_fd);
    if (build_fd >= 0) close(build_fd);
    if (root_fd >= 0) close(root_fd);
    if (root[0] != '\0') {
        snprintf(blob_path, sizeof(blob_path),
            "%s/.tm/blobs/sha256/2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            root);
        unlink(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/.tm/blobs/sha256", root); rmdir(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/.tm/blobs", root); rmdir(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/.tm", root); rmdir(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/artifact.txt", root); unlink(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/build/reports/sub/b.txt", root); unlink(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/build/reports/sub", root); rmdir(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/build/reports/a.txt", root); unlink(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/build/reports", root); rmdir(blob_path);
        snprintf(blob_path, sizeof(blob_path), "%s/build", root); rmdir(blob_path);
        rmdir(root);
    }
    return status;
}
