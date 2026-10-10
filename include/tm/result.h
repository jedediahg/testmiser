#ifndef TM_RESULT_H
#define TM_RESULT_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "tm/verification.h"

struct tm_result_policy {
    const char *repository_id;
    const char *approved_profile_digest;
    uint64_t minimum_trust_epoch;
    const char *expected_verification_fingerprint;
};

/* Build a signed v2 success record with an empty output manifest. The returned
 * JSON ends with exactly one LF. */
int tm_result_create(const struct tm_verification_identity *identity,
                     uint64_t trust_epoch, EVP_PKEY *private_key,
                     unsigned char **record, size_t *record_length,
                     char record_id[72]);

/* Authenticate and scope-check an output-free record using an
 * operator-approved key/policy. Nonempty outputs are rejected. */
int tm_result_verify(const unsigned char *record, size_t record_length,
                     EVP_PKEY *trusted_public_key,
                     const struct tm_result_policy *policy,
                     char record_id[72]);

#endif
