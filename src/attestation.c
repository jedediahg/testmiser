#include <errno.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "tm/attestation.h"
#include "tm/digest.h"

int tm_ed25519_sign(EVP_PKEY *private_key, const unsigned char *payload,
                    size_t payload_length,
                    unsigned char signature[TM_ED25519_SIGNATURE_SIZE])
{
    EVP_MD_CTX *context;
    size_t signature_length = TM_ED25519_SIGNATURE_SIZE;
    int result = -1;

    if (private_key == NULL || signature == NULL ||
        (payload == NULL && payload_length != 0) ||
        EVP_PKEY_is_a(private_key, "ED25519") != 1) {
        errno = EINVAL;
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (EVP_DigestSignInit(context, NULL, NULL, NULL, private_key) == 1 &&
        EVP_DigestSign(context, signature, &signature_length, payload,
                       payload_length) == 1 &&
        signature_length == TM_ED25519_SIGNATURE_SIZE) {
        result = 0;
    } else {
        errno = EIO;
    }
    EVP_MD_CTX_free(context);
    return result;
}

int tm_ed25519_verify(EVP_PKEY *public_key, const unsigned char *payload,
                      size_t payload_length,
                      const unsigned char signature[TM_ED25519_SIGNATURE_SIZE])
{
    EVP_MD_CTX *context;
    int verify_result;

    if (public_key == NULL || signature == NULL ||
        (payload == NULL && payload_length != 0) ||
        EVP_PKEY_is_a(public_key, "ED25519") != 1) {
        errno = EINVAL;
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL) {
        errno = ENOMEM;
        return -1;
    }
    if (EVP_DigestVerifyInit(context, NULL, NULL, NULL, public_key) != 1) {
        EVP_MD_CTX_free(context);
        errno = EIO;
        return -1;
    }
    verify_result = EVP_DigestVerify(context, signature,
                                     TM_ED25519_SIGNATURE_SIZE, payload,
                                     payload_length);
    EVP_MD_CTX_free(context);
    if (verify_result == 1) {
        return 0;
    }
    errno = verify_result == 0 ? EBADMSG : EIO;
    return -1;
}

int tm_ed25519_key_id(EVP_PKEY *public_key, char output[65])
{
    unsigned char *der = NULL;
    unsigned char *cursor;
    int der_length;
    int result;

    if (public_key == NULL || output == NULL ||
        EVP_PKEY_is_a(public_key, "ED25519") != 1) {
        errno = EINVAL;
        return -1;
    }
    der_length = i2d_PUBKEY(public_key, NULL);
    if (der_length <= 0) {
        errno = EIO;
        return -1;
    }
    der = OPENSSL_malloc((size_t)der_length);
    if (der == NULL) {
        errno = ENOMEM;
        return -1;
    }
    cursor = der;
    if (i2d_PUBKEY(public_key, &cursor) != der_length) {
        OPENSSL_free(der);
        errno = EIO;
        return -1;
    }
    result = tm_sha256_bytes(der, (size_t)der_length, output);
    OPENSSL_free(der);
    return result;
}
