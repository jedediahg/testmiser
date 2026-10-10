#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "tm/result.h"
#include "tm/trust.h"

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
    struct tm_result_summary summary = {0};
    const char *signature_marker = "\"signature\":\"";
    char *signature_text;
    struct tm_trust_policy *trust = NULL;
    char policy_path[] = "/tmp/tm-result-policy-XXXXXX";
    char input_root[] = "/tmp/tm-result-inputs-XXXXXX";
    char input_directory[256];
    char input_file[256];
    char policy_json[2048];
    unsigned char public_bytes[32];
    size_t public_length = sizeof(public_bytes);
    unsigned char public_b64[EVP_ENCODE_LENGTH(32)];
    int policy_fd = -1, input_root_fd = -1, input_file_fd = -1;
    int policy_length;
    int public_b64_length;

    if (private_key == NULL ||
        tm_result_create(&identity, 3, private_key, &record, &record_length,
                         record_id) != 0 ||
        strcmp(record_id, expected_id) != 0 ||
        record[record_length - 1] != '\n' ||
        tm_result_verify(record, record_length, private_key, &policy,
                         verified_id) != 0 ||
        strcmp(verified_id, expected_id) != 0 ||
        tm_result_inspect(record, record_length, &summary, verified_id) != 0 ||
        strcmp(summary.repository_id, "sample") != 0 ||
        strcmp(summary.command_id,
               "0000000000000000000000000000000000000000000000000000000000000000") != 0 ||
        strcmp(summary.verification_id,
               "ba299d5d7bd04d93e635617e6d2e496248711a9fa93bf4360a98c706ad201622") != 0 ||
        summary.input_count != 2 ||
        strcmp(summary.inputs[0].path, "tests/a") != 0 ||
        strcmp(summary.inputs[1].path, "tests/missing") != 0 ||
        strcmp(verified_id, expected_id) != 0) {
        fprintf(stderr, "signed result golden vector failed\n");
        goto fail;
    }
    tm_result_summary_clear(&summary);
    if (EVP_PKEY_get_raw_public_key(private_key, public_bytes,
                                    &public_length) != 1 ||
        public_length != sizeof(public_bytes)) goto fail;
    public_b64_length = EVP_EncodeBlock(public_b64, public_bytes,
                                        sizeof(public_bytes));
    if (public_b64_length != 44) goto fail;
    public_b64[public_b64_length] = '\0';
    policy_length = snprintf(policy_json, sizeof(policy_json),
        "{\"schema_version\":1,\"repositories\":[{"
        "\"repository_id\":\"sample\",\"minimum_trust_epoch\":3,"
        "\"allowed_semantics\":[2],"
        "\"profiles\":[\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"],"
        "\"keys\":[{\"key_id\":\"sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9\","
        "\"public_key\":\"%s\",\"role\":\"test\"}],\"revoked_key_ids\":[]}]}",
        public_b64);
    if (policy_length < 0 || policy_length >= (int)sizeof(policy_json)) goto fail;
    policy_fd = mkstemp(policy_path);
    if (policy_fd < 0) goto fail;
    if (write(policy_fd, policy_json, (size_t)policy_length) != policy_length) {
        close(policy_fd);
        policy_fd = -1;
        goto fail;
    }
    if (close(policy_fd) < 0) {
        policy_fd = -1;
        goto fail;
    }
    policy_fd = -1;
    if (tm_trust_policy_load(policy_path, &trust) != 0 ||
        tm_result_verify_trusted(record, record_length, trust,
                                 policy.expected_verification_fingerprint,
                                 verified_id) != 0 ||
        strcmp(verified_id, expected_id) != 0) {
        fprintf(stderr, "operator-policy result verification failed\n");
        goto fail;
    }
    if (tm_result_verify_trusted(
            record, record_length, trust,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            verified_id) == 0) {
        fprintf(stderr, "trusted verifier ignored current fingerprint\n");
        goto fail;
    }

    if (mkdtemp(input_root) == NULL) goto fail;
    snprintf(input_directory, sizeof(input_directory), "%s/tests", input_root);
    snprintf(input_file, sizeof(input_file), "%s/tests/a", input_root);
    if (mkdir(input_directory, 0700) < 0) goto fail;
    input_file_fd = open(input_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (input_file_fd < 0) goto fail;
    {
        int fd = input_file_fd;
        input_file_fd = -1;
        if (close(fd) < 0) goto fail;
    }
    input_root_fd = open(input_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (input_root_fd < 0 ||
        tm_result_verify_inputs_match(record, record_length, trust,
                                      input_root_fd, verified_id) != 0) {
        fprintf(stderr, "signed record input manifest did not match\n");
        goto fail;
    }
    input_file_fd = open(input_file, O_WRONLY | O_TRUNC);
    if (input_file_fd < 0 || write(input_file_fd, "changed", 7) != 7)
        goto fail;
    {
        int fd = input_file_fd;
        input_file_fd = -1;
        if (close(fd) < 0) goto fail;
    }
    if (tm_result_verify_inputs_match(record, record_length, trust,
                                      input_root_fd, verified_id) != 1) {
        fprintf(stderr, "signed record input change was not detected\n");
        goto fail;
    }
    if (tm_result_verify_inputs_match(tampered, record_length, trust,
                                      input_root_fd, verified_id) == 0) {
        fprintf(stderr, "tampered signed record passed trusted input check\n");
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
    if (tm_result_inspect(tampered, record_length, &summary, verified_id) != 0) {
        fprintf(stderr, "structural inspection required a trusted signature\n");
        goto fail;
    }
    tm_result_summary_clear(&summary);

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
    tm_result_summary_clear(&summary);
    tm_trust_policy_free(trust);
    unlink(policy_path);
    if (input_root_fd >= 0) close(input_root_fd);
    unlink(input_file);
    rmdir(input_directory);
    rmdir(input_root);
    EVP_PKEY_free(private_key);
    return 0;

fail:
    free(tampered);
    free(noncanonical);
    free(record);
    tm_result_summary_clear(&summary);
    if (policy_fd >= 0) close(policy_fd);
    if (input_file_fd >= 0) close(input_file_fd);
    if (input_root_fd >= 0) close(input_root_fd);
    tm_trust_policy_free(trust);
    unlink(policy_path);
    unlink(input_file);
    rmdir(input_directory);
    rmdir(input_root);
    EVP_PKEY_free(private_key);
    return 1;
}
