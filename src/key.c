#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/attestation.h"
#include "tm/key.h"

static int reject_key_password(char *buffer, int size, int writing,
                               void *userdata)
{
    (void)buffer;
    (void)size;
    (void)writing;
    (void)userdata;
    return 0;
}

int tm_key_generate(const char *path)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;
    unsigned char public_key[32];
    unsigned char encoded[EVP_ENCODE_LENGTH(sizeof(public_key))];
    size_t public_length = sizeof(public_key);
    char key_id[72];
    struct stat status;
    int descriptor = -1;
    int encoded_length;
    int status_valid = 0;
    int result = -1;
    int saved;

    if (path == NULL || path[0] == '\0') { errno = EINVAL; return -1; }
    context = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_generate(context, &key) <= 0 ||
        EVP_PKEY_get_raw_public_key(key, public_key, &public_length) != 1 ||
        public_length != sizeof(public_key) ||
        tm_ed25519_key_id(key, key_id) < 0) {
        errno = EIO;
        goto done;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                              O_NOFOLLOW, 0600);
    if (descriptor < 0) goto done;
    if (fstat(descriptor, &status) < 0) goto done;
    status_valid = 1;
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0 || status.st_nlink != 1) {
        errno = EACCES;
        goto done;
    }
    bio = BIO_new_fd(descriptor, BIO_NOCLOSE);
    if (bio == NULL) { errno = EIO; goto done; }
    if (PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) != 1 ||
        BIO_flush(bio) != 1) {
        errno = EIO;
        goto done;
    }
    if (fsync(descriptor) < 0) goto done;
    encoded_length = EVP_EncodeBlock(encoded, public_key,
                                     (int)sizeof(public_key));
    if (encoded_length != 44) { errno = EIO; goto done; }
    encoded[encoded_length] = '\0';
    if (printf("{\"key_id\":\"%s\",\"public_key\":\"%s\"}\n",
               key_id, encoded) < 0 || fflush(stdout) == EOF) {
        errno = EIO;
        goto done;
    }
    result = 0;
done:
    saved = errno;
    BIO_free(bio);
    if (descriptor >= 0) {
        close(descriptor);
        if (result < 0 && status_valid) {
            struct stat current;
            if (fstatat(AT_FDCWD, path, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
                current.st_dev == status.st_dev &&
                current.st_ino == status.st_ino)
                (void)unlink(path);
        }
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    errno = saved;
    return result;
}

int tm_key_load_private(const char *path, EVP_PKEY **key)
{
    struct stat status;
    BIO *bio = NULL;
    EVP_PKEY *loaded = NULL;
    int descriptor = -1, saved;
    if (path == NULL || path[0] == '\0' || key == NULL) {
        errno = EINVAL;
        return -1;
    }
    *key = NULL;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &status) < 0) goto done;
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() ||
        (status.st_mode & 077) != 0 || status.st_nlink != 1 ||
        status.st_size <= 0 || status.st_size > 1024 * 1024) {
        errno = EACCES;
        goto done;
    }
    bio = BIO_new_fd(descriptor, BIO_CLOSE);
    if (bio == NULL) { errno = ENOMEM; goto done; }
    descriptor = -1;
    loaded = PEM_read_bio_PrivateKey(bio, NULL, reject_key_password, NULL);
    if (loaded == NULL || EVP_PKEY_is_a(loaded, "ED25519") != 1) {
        errno = EINVAL;
        goto done;
    }
    *key = loaded;
    loaded = NULL;
    BIO_free(bio);
    return 0;
done:
    saved = errno;
    BIO_free(bio);
    if (descriptor >= 0) close(descriptor);
    EVP_PKEY_free(loaded);
    errno = saved;
    return -1;
}
