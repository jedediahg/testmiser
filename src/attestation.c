#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "tm/attestation.h"
#include "tm/digest.h"

static unsigned char *result_preimage(const unsigned char *payload,
                                      size_t payload_length,
                                      size_t *preimage_length)
{
    static const unsigned char domain[] = "tm-result-v2";
    unsigned char *preimage;

    if (payload_length > SIZE_MAX - sizeof(domain)) {
        errno = EOVERFLOW;
        return NULL;
    }
    preimage = malloc(sizeof(domain) + payload_length);
    if (preimage == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    memcpy(preimage, domain, sizeof(domain));
    if (payload_length > 0) {
        memcpy(preimage + sizeof(domain), payload, payload_length);
    }
    *preimage_length = sizeof(domain) + payload_length;
    return preimage;
}

int tm_ed25519_sign(EVP_PKEY *private_key, const unsigned char *payload,
                    size_t payload_length,
                    unsigned char signature[TM_ED25519_SIGNATURE_SIZE])
{
    EVP_MD_CTX *context;
    unsigned char *preimage;
    size_t preimage_length;
    size_t signature_length = TM_ED25519_SIGNATURE_SIZE;
    int result = -1;

    if (private_key == NULL || signature == NULL ||
        (payload == NULL && payload_length != 0) ||
        EVP_PKEY_is_a(private_key, "ED25519") != 1) {
        errno = EINVAL;
        return -1;
    }
    preimage = result_preimage(payload, payload_length, &preimage_length);
    if (preimage == NULL) {
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL) {
        free(preimage);
        errno = ENOMEM;
        return -1;
    }
    if (EVP_DigestSignInit(context, NULL, NULL, NULL, private_key) == 1 &&
        EVP_DigestSign(context, signature, &signature_length, preimage,
                       preimage_length) == 1 &&
        signature_length == TM_ED25519_SIGNATURE_SIZE) {
        result = 0;
    } else {
        errno = EIO;
    }
    EVP_MD_CTX_free(context);
    free(preimage);
    return result;
}

int tm_ed25519_verify(EVP_PKEY *public_key, const unsigned char *payload,
                      size_t payload_length,
                      const unsigned char signature[TM_ED25519_SIGNATURE_SIZE])
{
    EVP_MD_CTX *context;
    unsigned char *preimage;
    size_t preimage_length;
    int verify_result;

    if (public_key == NULL || signature == NULL ||
        (payload == NULL && payload_length != 0) ||
        EVP_PKEY_is_a(public_key, "ED25519") != 1) {
        errno = EINVAL;
        return -1;
    }
    preimage = result_preimage(payload, payload_length, &preimage_length);
    if (preimage == NULL) {
        return -1;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL) {
        free(preimage);
        errno = ENOMEM;
        return -1;
    }
    if (EVP_DigestVerifyInit(context, NULL, NULL, NULL, public_key) != 1) {
        EVP_MD_CTX_free(context);
        free(preimage);
        errno = EIO;
        return -1;
    }
    verify_result = EVP_DigestVerify(context, signature,
                                     TM_ED25519_SIGNATURE_SIZE, preimage,
                                     preimage_length);
    EVP_MD_CTX_free(context);
    free(preimage);
    if (verify_result == 1) {
        return 0;
    }
    errno = verify_result == 0 ? EBADMSG : EIO;
    return -1;
}

int tm_ed25519_key_id(EVP_PKEY *public_key, char output[72])
{
    unsigned char raw_public_key[32];
    size_t raw_public_key_length = sizeof(raw_public_key);
    char digest[65];

    if (public_key == NULL || output == NULL ||
        EVP_PKEY_is_a(public_key, "ED25519") != 1) {
        errno = EINVAL;
        return -1;
    }
    if (EVP_PKEY_get_raw_public_key(public_key, raw_public_key,
                                    &raw_public_key_length) != 1 ||
        raw_public_key_length != sizeof(raw_public_key)) {
        errno = EIO;
        return -1;
    }
    if (tm_sha256_bytes(raw_public_key, sizeof(raw_public_key), digest) < 0) {
        return -1;
    }
    memcpy(output, "sha256:", 7);
    memcpy(output + 7, digest, sizeof(digest));
    return 0;
}
