#ifndef TM_RESULT_H
#define TM_RESULT_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "tm/verification.h"

struct tm_trust_policy;

struct tm_result_policy {
    const char *repository_id;
    const char *approved_profile_digest;
    uint64_t minimum_trust_epoch;
    const char *expected_verification_fingerprint;
};

struct tm_result_summary {
    char *repository_id;
    char *profile_digest;
    char *key_id;
    char *verification_fingerprint;
    char command_id[65];
    char verification_id[65];
    uint64_t trust_epoch;
    uint64_t semantics_version;
    struct tm_input_observation *inputs;
    size_t input_count;
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

/* Resolve the claimed repository/profile/key from operator policy, then verify
 * the record against a freshly computed current fingerprint. */
int tm_result_verify_trusted(const unsigned char *record, size_t record_length,
                             const struct tm_trust_policy *trust_policy,
                             const char *expected_verification_fingerprint,
                             char record_id[72]);

/* Validate canonical structure and reconstruct the fingerprint without
 * asserting that the signature is trusted or that current files are fresh.
 * String fields and the owned input manifest are released by summary_clear. */
int tm_result_inspect(const unsigned char *record, size_t record_length,
                      struct tm_result_summary *summary, char record_id[72]);

/* Verify a signed record under operator policy, then compare its observed
 * manifest with a current repository view. Return 0 for trusted+matching, 1
 * for trusted+changed inputs, and -1 for invalid/untrusted/unsafe state. This
 * does not establish observation completeness or context equivalence. */
int tm_result_verify_inputs_match(
    const unsigned char *record, size_t record_length,
    const struct tm_trust_policy *trust_policy, int repository_root_fd,
    char record_id[72]);
void tm_result_summary_clear(struct tm_result_summary *summary);

#endif
