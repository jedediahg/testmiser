#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/digest.h"

static int format_digest(const unsigned char digest[32], char output[65])
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < 32; index++) {
        output[index * 2] = digits[digest[index] >> 4];
        output[index * 2 + 1] = digits[digest[index] & 0x0f];
    }
    output[64] = '\0';
    return 0;
}

int tm_sha256_bytes(const void *data, size_t length, char output[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;

    if ((data == NULL && length != 0) || output == NULL ||
        EVP_Digest(data, length, digest, &digest_length, EVP_sha256(), NULL) != 1 ||
        digest_length != 32) {
        errno = EINVAL;
        return -1;
    }
    return format_digest(digest, output);
}

static int same_file_version(const struct stat *before,
                             const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_mode == after->st_mode && before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

int tm_sha256_file(const char *path, char output[65])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned char buffer[32768];
    EVP_MD_CTX *context;
    struct stat before;
    struct stat after;
    unsigned int digest_length = 0;
    int descriptor;
    int saved_errno;

    if (path == NULL || output == NULL) {
        errno = EINVAL;
        return -1;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    if (fstat(descriptor, &before) < 0) {
        saved_errno = errno;
        close(descriptor);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(before.st_mode)) {
        close(descriptor);
        errno = EINVAL;
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(context);
        close(descriptor);
        errno = EIO;
        return -1;
    }
    for (;;) {
        ssize_t count = read(descriptor, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            goto fail;
        }
        if (count == 0) {
            break;
        }
        if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) {
            errno = EIO;
            goto fail;
        }
    }
    if (fstat(descriptor, &after) < 0) {
        goto fail;
    }
    if (!same_file_version(&before, &after)) {
        errno = EBUSY;
        goto fail;
    }
    if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length != 32) {
        errno = EIO;
        goto fail;
    }
    EVP_MD_CTX_free(context);
    close(descriptor);
    return format_digest(digest, output);

fail:
    saved_errno = errno;
    EVP_MD_CTX_free(context);
    close(descriptor);
    errno = saved_errno;
    return -1;
}
