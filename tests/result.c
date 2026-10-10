#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "tm/result.h"

static int must_reject(const unsigned char *record, size_t length,
                       EVP_PKEY *key, const struct tm_result_policy *policy)
{
    char record_id[72];
    return tm_result_verify(record, length, key, policy, record_id) != 0;
}

int main(void)
{
    static const unsigned char seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    const struct tm_input_observation inputs[] = {
        {"tests/missing", TM_INPUT_EXISTS, NULL, NULL, 0},
        {"tests/a", TM_INPUT_FILE,
         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         NULL, 0},
        {"tests/a", TM_INPUT_FILE,
         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         NULL, 0}
    };
    struct tm_verification_identity identity = {
        "sample",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "subdir",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        inputs, 3
    };
    const struct tm_result_policy policy = {
        "sample",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        3,
        "sha256:ba299d5d7bd04d93e635617e6d2e496248711a9fa93bf4360a98c706ad201622"
    };
    const char *expected_id =
        "sha256:be570567c32c611183e878038c38f8970fba874b7ee15758597b45b11c52a88c";
    EVP_PKEY *private_key = EVP_PKEY_new_raw_private_key_ex(
        NULL, "ED25519", NULL, seed, sizeof(seed));
    unsigned char *record = NULL;
    unsigned char *tampered = NULL;
    unsigned char *noncanonical = NULL;
    size_t record_length = 0;
    char record_id[72];
    char verified_id[72];
    const char *signature_marker = "\"signature\":\"";
    char *signature_text;

    if (private_key == NULL ||
        tm_result_create(&identity, 3, private_key, &record, &record_length,
                         record_id) != 0 ||
        strcmp(record_id, expected_id) != 0 ||
        record[record_length - 1] != '\n' ||
        tm_result_verify(record, record_length, private_key, &policy,
                         verified_id) != 0 ||
        strcmp(verified_id, expected_id) != 0) {
        fprintf(stderr, "signed result golden vector failed\n");
        goto fail;
    }

    tampered = malloc(record_length + 1);
    noncanonical = malloc(record_length + 2);
    if (tampered == NULL || noncanonical == NULL) goto fail;
    memcpy(tampered, record, record_length + 1);
    signature_text = strstr((char *)tampered, signature_marker);
    if (signature_text == NULL) goto fail;
    signature_text += strlen(signature_marker);
    signature_text[0] = signature_text[0] == 'A' ? 'B' : 'A';
    if (!must_reject(tampered, record_length, private_key, &policy)) {
        fprintf(stderr, "tampered signature was accepted\n");
        goto fail;
    }

    noncanonical[0] = ' ';
    memcpy(noncanonical + 1, record, record_length);
    noncanonical[record_length + 1] = '\0';
    if (!must_reject(noncanonical, record_length + 1, private_key, &policy)) {
        fprintf(stderr, "noncanonical signed record was accepted\n");
        goto fail;
    }
    if (!must_reject(record, record_length - 1, private_key, &policy)) {
        fprintf(stderr, "record without required LF was accepted\n");
        goto fail;
    }

    {
        struct tm_result_policy wrong = policy;
        wrong.repository_id = "another-project";
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
        wrong = policy;
        wrong.approved_profile_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
        wrong = policy;
        wrong.minimum_trust_epoch = 4;
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
        wrong = policy;
        wrong.expected_verification_fingerprint =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
    }

    free(tampered);
    free(noncanonical);
    free(record);
    EVP_PKEY_free(private_key);
    return 0;

fail:
    free(tampered);
    free(noncanonical);
    free(record);
    EVP_PKEY_free(private_key);
    return 1;
}
