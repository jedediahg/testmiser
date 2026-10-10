#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#include "tm/attestation.h"

int main(void)
{
    EVP_PKEY_CTX *key_context = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char signature[TM_ED25519_SIGNATURE_SIZE];
    const unsigned char payload[] = "canonical payload bytes";
    unsigned char changed[] = "canonical payload byteS";
    char key_id[65];
    int result = 1;

    key_context = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    if (key_context == NULL || EVP_PKEY_keygen_init(key_context) != 1 ||
        EVP_PKEY_generate(key_context, &private_key) != 1 ||
        tm_ed25519_sign(private_key, payload, sizeof(payload) - 1,
                        signature) != 0 ||
        EVP_PKEY_up_ref(private_key) != 1) {
        fprintf(stderr, "Ed25519 test setup failed\n");
        goto done;
    }
    public_key = private_key;
    if (tm_ed25519_verify(public_key, payload, sizeof(payload) - 1,
                          signature) != 0 ||
        tm_ed25519_key_id(public_key, key_id) != 0 || strlen(key_id) != 64) {
        fprintf(stderr, "Ed25519 verification test failed\n");
        goto done;
    }
    if (tm_ed25519_verify(public_key, changed, sizeof(changed) - 1,
                          signature) == 0) {
        fprintf(stderr, "Ed25519 accepted modified payload\n");
        goto done;
    }
    result = 0;

done:
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(key_context);
    return result;
}
