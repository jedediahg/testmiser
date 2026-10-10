#ifndef TM_RESULT_H
#define TM_RESULT_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>

#include "tm/outputs.h"
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
    struct tm_output_entry *outputs;
    size_t output_count;
};

/* Build a signed v2 success record with an empty output manifest. The returned
 * JSON ends with exactly one LF. */
int tm_result_create(const struct tm_verification_identity *identity,
                     uint64_t trust_epoch, EVP_PKEY *private_key,
                     unsigned char **record, size_t *record_length,
                     char record_id[72]);

/* Build a signed v2 success record with a captured output manifest. The
 * referenced blob store must remain available for a future restore. */
int tm_result_create_with_outputs(
    const struct tm_verification_identity *identity, uint64_t trust_epoch,
    EVP_PKEY *private_key, const struct tm_output_manifest *outputs,
    unsigned char **record, size_t *record_length, char record_id[72]);

/* Atomically add a canonical record to .tm/results using the portable
 * command/verification/record ID layout. Existing IDs are never replaced. */
int tm_result_store(int repository_root_fd, const unsigned char *record,
                    size_t record_length, char record_id[72]);

/* Find a trusted result for exact command and verification fingerprints.
 * Return 0 with owned record bytes on hit, 1 on miss, or -1 on error. */
int tm_result_find(int repository_root_fd, const char *command_fingerprint,
                   const char *verification_fingerprint,
                   const struct tm_trust_policy *trust_policy,
                   unsigned char **record, size_t *record_length,
                   char record_id[72]);

/* Find an output-free trusted record in a separate shared store while
 * validating its inputs against the current repository checkout. */
int tm_result_find_in_store(int store_root_fd, int repository_root_fd,
                            const char *command_fingerprint,
                            const char *verification_fingerprint,
                            const struct tm_trust_policy *trust_policy,
                            unsigned char **record, size_t *record_length,
                            char record_id[72]);

/* Find and authenticate a result, check its declared inputs, restore the
 * caller's declared output roots, and return a hit only after restoration.
 * Output roots must be the same declarations bound into command_fingerprint. */
int tm_result_find_and_restore(
    int repository_root_fd, const char *command_fingerprint,
    const char *verification_fingerprint,
    const struct tm_trust_policy *trust_policy,
    const char *const *output_roots, size_t output_root_count,
    unsigned char **record, size_t *record_length, char record_id[72]);

/* Authenticate and scope-check a record, including its declared output
 * manifest, using an operator-approved key/policy. */
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
 * String fields and owned input/output manifests are released by summary_clear. */
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
