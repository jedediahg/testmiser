#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "tm/attestation.h"
#include "tm/trust.h"

static int write_policy(const char *path, const char *contents)
{
    int descriptor = open(path, O_WRONLY | O_TRUNC);
    size_t length = strlen(contents);
    size_t offset = 0;
    if (descriptor < 0) return -1;
    while (offset < length) {
        ssize_t count = write(descriptor, contents + offset, length - offset);
        if (count < 0) {
            close(descriptor);
            return -1;
        }
        offset += (size_t)count;
    }
    return close(descriptor);
}

int main(void)
{
    static const unsigned char seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    const char *profile =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const char *wrong_profile =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    EVP_PKEY *key = NULL;
    EVP_PKEY *resolved = NULL;
    struct tm_trust_policy *policy = NULL;
    char key_id[72];
    unsigned char public_bytes[32];
    size_t public_length = sizeof(public_bytes);
    unsigned char encoded[EVP_ENCODE_LENGTH(32)];
    char path[] = "/tmp/tm-trust-test-XXXXXX";
    char json[2048];
    int descriptor = -1;
    int encoded_length;
    int status = 1;
    char revoked_json[2048];

    key = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, seed,
                                          sizeof(seed));
    if (key == NULL || tm_ed25519_key_id(key, key_id) != 0 ||
        EVP_PKEY_get_raw_public_key(key, public_bytes, &public_length) != 1 ||
        public_length != sizeof(public_bytes)) goto done;
    encoded_length = EVP_EncodeBlock(encoded, public_bytes, sizeof(public_bytes));
    if (encoded_length != 44) goto done;
    encoded[encoded_length] = '\0';
    if (snprintf(json, sizeof(json),
        "{\"schema_version\":1,\"repositories\":[{"
        "\"repository_id\":\"sample\",\"minimum_trust_epoch\":2,"
        "\"allowed_semantics\":[2],\"profiles\":[\"%s\"],"
        "\"keys\":[{\"key_id\":\"%s\",\"public_key\":\"%s\","
        "\"role\":\"developer\"}],\"revoked_key_ids\":[]}]}",
        profile, key_id, encoded) >= (int)sizeof(json)) goto done;
    descriptor = mkstemp(path);
    if (descriptor < 0) goto done;
    if (close(descriptor) < 0) {
        descriptor = -1;
        goto done;
    }
    descriptor = -1;
    if (write_policy(path, json) < 0 ||
        tm_trust_policy_load(path, &policy) != 0 ||
        tm_trust_policy_authorize(policy, "sample", profile, key_id, 2, 2,
                                  &resolved) != 0 ||
        resolved == NULL) goto done;
    EVP_PKEY_free(resolved);
    resolved = NULL;
    if (tm_trust_policy_approves_profile(policy, "sample", profile) != 0 ||
        tm_trust_policy_approves_profile(policy, "sample", wrong_profile) == 0 ||
        tm_trust_policy_approves_profile(policy, "missing", profile) == 0) {
        fprintf(stderr, "trust policy profile approval mismatch\n");
        goto done;
    }

    if (tm_trust_policy_authorize(policy, "other", profile, key_id, 2, 2,
                                  &resolved) == 0 ||
        tm_trust_policy_authorize(policy, "sample", wrong_profile, key_id, 2, 2,
                                  &resolved) == 0 ||
        tm_trust_policy_authorize(policy, "sample", profile, key_id, 1, 2,
                                  &resolved) == 0 ||
        tm_trust_policy_authorize(policy, "sample", profile, key_id, 2, 1,
                                  &resolved) == 0) {
        fprintf(stderr, "trust policy accepted an out-of-scope result\n");
        goto done;
    }
    if (tm_trust_policy_classify(policy, "sample", profile, key_id, 1, 2,
                                 &resolved) != TM_TRUST_STALE_EPOCH ||
        resolved == NULL) goto done;
    EVP_PKEY_free(resolved);
    resolved = NULL;
    if (tm_trust_policy_classify(policy, "sample", wrong_profile, key_id,
                                 2, 2, &resolved) !=
            TM_TRUST_UNAPPROVED_PROFILE || resolved == NULL) goto done;
    EVP_PKEY_free(resolved);
    resolved = NULL;
    if (tm_trust_policy_classify(policy, "missing", profile, key_id, 2, 2,
                                 &resolved) != TM_TRUST_UNKNOWN_REPOSITORY ||
        resolved != NULL) goto done;

    tm_trust_policy_free(policy);
    policy = NULL;
    if (snprintf(revoked_json, sizeof(revoked_json),
        "{\"schema_version\":1,\"repositories\":[{"
        "\"repository_id\":\"sample\",\"minimum_trust_epoch\":2,"
        "\"allowed_semantics\":[2],\"profiles\":[\"%s\"],"
        "\"keys\":[{\"key_id\":\"%s\",\"public_key\":\"%s\","
        "\"role\":\"developer\"}],\"revoked_key_ids\":[\"%s\"]}]}",
        profile, key_id, encoded, key_id) >= (int)sizeof(revoked_json) ||
        write_policy(path, revoked_json) < 0 ||
        tm_trust_policy_load(path, &policy) != 0 ||
        tm_trust_policy_authorize(policy, "sample", profile, key_id, 2, 2,
                                  &resolved) == 0) {
        fprintf(stderr, "trust policy accepted a revoked key\n");
        goto done;
    }
    tm_trust_policy_free(policy);
    policy = NULL;
    if (write_policy(path,
          "{\"schema_version\":1,\"schema_version\":1,\"repositories\":[]}") == 0 &&
        tm_trust_policy_load(path, &policy) == 0) {
        fprintf(stderr, "trust policy accepted duplicate JSON keys\n");
        goto done;
    }
    tm_trust_policy_free(policy);
    policy = NULL;
    if (write_policy(path, json) < 0 || chmod(path, 0666) < 0 ||
        tm_trust_policy_load(path, &policy) == 0) {
        fprintf(stderr, "trust policy accepted a writable policy file\n");
        goto done;
    }
    status = 0;

done:
    if (descriptor >= 0) close(descriptor);
    unlink(path);
    EVP_PKEY_free(resolved);
    EVP_PKEY_free(key);
    tm_trust_policy_free(policy);
    return status;
}
