#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tm/digest.h"

static int check_bytes(const void *bytes, size_t length, const char *expected)
{
    char digest[65];

    return tm_sha256_bytes(bytes, length, digest) == 0 &&
           strcmp(digest, expected) == 0;
}

int main(void)
{
    char path[] = "/tmp/tm-digest-test-XXXXXX";
    char digest[65];
    int descriptor;
    int result = 1;

    if (!check_bytes("", 0,
                     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") ||
        !check_bytes("abc", 3,
                     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
        fprintf(stderr, "digest byte test failed\n");
        return 1;
    }
    descriptor = mkstemp(path);
    if (descriptor < 0) {
        perror("digest test setup");
        return 1;
    }
    if (write(descriptor, "abc", 3) != 3) {
        perror("digest test write");
        close(descriptor);
        unlink(path);
        return 1;
    }
    if (close(descriptor) < 0) {
        perror("digest test close");
        unlink(path);
        return 1;
    }
    if (tm_sha256_file(path, digest) == 0 &&
        strcmp(digest,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0) {
        result = 0;
    } else {
        fprintf(stderr, "digest file test failed\n");
    }
    unlink(path);
    return result;
}
