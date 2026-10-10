#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/digest.h"
#include "tm/input.h"

static int write_file(const char *path, const char *value)
{
    size_t length = strlen(value), offset = 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    while (offset < length) {
        ssize_t n = write(fd, value + offset, length - offset);
        if (n < 0) { close(fd); return -1; }
        offset += (size_t)n;
    }
    return close(fd);
}

int main(void)
{
    char directory[] = "/tmp/tm-input-test-XXXXXX";
    char alpha[256], link_path[256], sub[256], nested[256];
    char file_hex[65], file_digest[72];
    int root = -1, status = 1;
    struct tm_input_observation input;

    if (mkdtemp(directory) == NULL) return 1;
    snprintf(alpha, sizeof(alpha), "%s/alpha", directory);
    snprintf(link_path, sizeof(link_path), "%s/link", directory);
    snprintf(sub, sizeof(sub), "%s/sub", directory);
    snprintf(nested, sizeof(nested), "%s/sub/item", directory);
    if (write_file(alpha, "hello\n") < 0 || mkdir(sub, 0700) < 0 ||
        symlink("alpha", link_path) < 0 ||
        tm_sha256_bytes("hello\n", 6, file_hex) < 0) goto done;
    snprintf(file_digest, sizeof(file_digest), "sha256:%s", file_hex);
    root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) goto done;

    input = (struct tm_input_observation){"alpha", TM_INPUT_FILE,
                                          file_digest, NULL, 0};
    if (tm_input_matches(root, &input) != 0) goto done;
    input = (struct tm_input_observation){"alpha", TM_INPUT_EXISTS,
                                          NULL, NULL, 1};
    if (tm_input_matches(root, &input) != 0) goto done;
    input = (struct tm_input_observation){"missing", TM_INPUT_EXISTS,
                                          NULL, NULL, 0};
    if (tm_input_matches(root, &input) != 0) goto done;
    input = (struct tm_input_observation){"link", TM_INPUT_SYMLINK,
                                          NULL, "alpha", 0};
    if (tm_input_matches(root, &input) != 0) goto done;
    input = (struct tm_input_observation){"sub", TM_INPUT_DIRECTORY,
        "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        NULL, 0};
    if (tm_input_matches(root, &input) != 0 || write_file(nested, "x") < 0 ||
        tm_input_matches(root, &input) != 1) {
        fprintf(stderr, "directory membership digest check failed\n");
        goto done;
    }

    input.path = "link/alpha";
    input.kind = TM_INPUT_FILE;
    if (tm_input_matches(root, &input) != -1) {
        fprintf(stderr, "symlink traversal was not rejected\n");
        goto done;
    }

    if (write_file(alpha, "changed\n") < 0) goto done;
    input = (struct tm_input_observation){"alpha", TM_INPUT_FILE,
                                          file_digest, NULL, 0};
    if (tm_input_matches(root, &input) != 1) {
        fprintf(stderr, "changed file content matched old digest\n");
        goto done;
    }
    status = 0;
done:
    if (root >= 0) close(root);
    unlink(nested);
    unlink(link_path);
    unlink(alpha);
    rmdir(sub);
    rmdir(directory);
    return status;
}
