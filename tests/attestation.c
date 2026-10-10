#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
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
    char key_id[72];
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
        tm_ed25519_key_id(public_key, key_id) != 0 || strlen(key_id) != 71) {
        fprintf(stderr, "Ed25519 verification test failed\n");
        goto done;
    }
    if (tm_ed25519_verify(public_key, changed, sizeof(changed) - 1,
                          signature) == 0) {
        fprintf(stderr, "Ed25519 accepted modified payload\n");
        goto done;
    }
    {
        static const unsigned char rfc8032_private_seed[32] = {
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        };
        static const char expected_signature[] =
            "08466e41af66a707b5c8b892e4080cc578508b4d90d4c741b3ed04c42dbaf17e"
            "c4babfea576ef4dfa70970b49a9fb4dd9c642d0d5b3bf493e0ffa3401c99fc0d";
        unsigned char expected[TM_ED25519_SIGNATURE_SIZE];
        unsigned char known_signature[TM_ED25519_SIGNATURE_SIZE];
        EVP_PKEY *known_private_key = EVP_PKEY_new_raw_private_key_ex(
            NULL, "ED25519", NULL, rfc8032_private_seed,
            sizeof(rfc8032_private_seed));
        size_t index;
        int vector_matches = known_private_key != NULL;

        for (index = 0; index < sizeof(expected); index++) {
            char byte_text[3] = {expected_signature[index * 2],
                                 expected_signature[index * 2 + 1], '\0'};
            expected[index] = (unsigned char)strtoul(byte_text, NULL, 16);
        }
        if (vector_matches &&
            tm_ed25519_sign(known_private_key,
                            (const unsigned char *)"payload", 7,
                            known_signature) == 0) {
            vector_matches = memcmp(known_signature, expected,
                                    sizeof(expected)) == 0;
        } else {
            vector_matches = 0;
        }
        EVP_PKEY_free(known_private_key);
        if (!vector_matches) {
            fprintf(stderr, "Ed25519 result signature vector failed\n");
            goto done;
        }
    }
    {
        static const unsigned char rfc8032_public_key[32] = {
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
            0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
            0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
        };
        static const char expected_key_id[] =
            "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
        EVP_PKEY *known_key = EVP_PKEY_new_raw_public_key_ex(
            NULL, "ED25519", NULL, rfc8032_public_key,
            sizeof(rfc8032_public_key));
        int known_key_matches = known_key != NULL &&
            tm_ed25519_key_id(known_key, key_id) == 0 &&
            strcmp(key_id, expected_key_id) == 0;
        EVP_PKEY_free(known_key);
        if (!known_key_matches) {
            fprintf(stderr, "Ed25519 public-key ID vector failed\n");
            goto done;
        }
    }
    result = 0;

done:
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    EVP_PKEY_CTX_free(key_context);
    return result;
}
