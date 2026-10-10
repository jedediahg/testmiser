#ifndef TM_DIGEST_H
#define TM_DIGEST_H

#include <stddef.h>

/* Write a lowercase, 64-character SHA-256 digest and a trailing NUL. */
int tm_sha256_bytes(const void *data, size_t length, char output[65]);

/* Hash a regular file, rejecting files that change while they are read. */
int tm_sha256_file(const char *path, char output[65]);

#endif
