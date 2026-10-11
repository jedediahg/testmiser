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
    char *tm_version;
    char *repository_id;
    char *profile_digest;
    char *runtime_digest;
    char *context_digest;
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

struct tm_result_lookup_diagnostics {
    int trust_rejected;
    int inputs_changed;
    int context_changed;
};

/* Build a schema-v3 signed success record (semantics v2) with an empty output
 * manifest. The returned JSON ends with exactly one LF. */
int tm_result_create(const struct tm_verification_identity *identity,
                     uint64_t trust_epoch, EVP_PKEY *private_key,
                     unsigned char **record, size_t *record_length,
                     char record_id[72]);

/* Build a schema-v3 signed success record with a captured output manifest.
 * The referenced blob store must remain available for a future restore. */
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

/* Search every immutable verification slot for the same command and public
 * execution context, then return a trusted output-free record whose recorded
 * inputs still match this checkout. */
int tm_result_find_matching_inputs(
    int store_root_fd, int repository_root_fd,
    const char *command_fingerprint,
    const char *profile_digest, const char *runtime_digest,
    const char *context_digest, const struct tm_trust_policy *trust_policy,
    unsigned char **record, size_t *record_length, char record_id[72]);
/* As above, but compare each authenticated candidate's manifest against the
 * approved input snapshots rather than the mutable checkout. */
int tm_result_find_matching_snapshot_inputs(
    int store_root_fd, const char *command_fingerprint,
    const char *profile_digest, const char *runtime_digest,
    const char *context_digest, const struct tm_trust_policy *trust_policy,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count, unsigned char **record, size_t *record_length,
    char record_id[72]);
/* As above, but accept output-bearing records without restoring their outputs.
 * Intended for audits that need to compare a later outcome to prior evidence. */
int tm_result_find_matching_snapshot_record(
    int store_root_fd, const char *command_fingerprint,
    const char *profile_digest, const char *runtime_digest,
    const char *context_digest, const struct tm_trust_policy *trust_policy,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count, unsigned char **record, size_t *record_length,
    char record_id[72]);
/* Diagnostic variant: report policy rejection, changed inputs, or changed
 * context only for structurally valid candidates in the same command/profile. */
int tm_result_find_matching_snapshot_record_diagnostic(
    int store_root_fd, const char *command_fingerprint,
    const char *profile_digest, const char *runtime_digest,
    const char *context_digest, const struct tm_trust_policy *trust_policy,
    const char *const *root_paths, const int *root_descriptors,
    size_t root_count, unsigned char **record, size_t *record_length,
    char record_id[72], struct tm_result_lookup_diagnostics *diagnostics);
/* Snapshot-input variant that also restores the authenticated output tree
 * before reporting a hit. */
int tm_result_find_matching_snapshot_inputs_and_restore(
    int store_root_fd, int repository_root_fd, int blob_store_root_fd,
    const char *command_fingerprint, const char *profile_digest,
    const char *runtime_digest, const char *context_digest,
    const struct tm_trust_policy *trust_policy,
    const char *const *snapshot_root_paths,
    const int *snapshot_root_descriptors, size_t snapshot_root_count,
    const char *const *output_roots, size_t output_root_count,
    unsigned char **record, size_t *record_length, char record_id[72]);
/* Snapshot lookup that refuses locally failed or quarantined fingerprints
 * before restoring their outputs. */
int tm_result_find_matching_snapshot_inputs_and_restore_blocked(
    int store_root_fd, int repository_root_fd, int blob_store_root_fd,
    const char *command_fingerprint, const char *profile_digest,
    const char *runtime_digest, const char *context_digest,
    const struct tm_trust_policy *trust_policy,
    const char *const *snapshot_root_paths,
    const int *snapshot_root_descriptors, size_t snapshot_root_count,
    const char *const *output_roots, size_t output_root_count,
    const char *const *blocked_fingerprints, size_t blocked_count,
    unsigned char **record, size_t *record_length, char record_id[72]);

/* As above, but restore the signed output manifest from the shared blob store
 * before returning a hit. The output roots are bound into command identity. */
int tm_result_find_matching_inputs_and_restore(
    int store_root_fd, int repository_root_fd, int blob_store_root_fd,
    const char *command_fingerprint,
    const char *profile_digest, const char *runtime_digest,
    const char *context_digest, const struct tm_trust_policy *trust_policy,
    const char *const *output_roots, size_t output_root_count,
    unsigned char **record, size_t *record_length, char record_id[72]);

/* Find and authenticate a result, check its declared inputs, restore the
 * caller's declared output roots, and return a hit only after restoration.
 * Output roots must be the same declarations bound into command_fingerprint. */
int tm_result_find_and_restore(
    int repository_root_fd, const char *command_fingerprint,
    const char *verification_fingerprint,
    const struct tm_trust_policy *trust_policy,
    const char *const *output_roots, size_t output_root_count,
    unsigned char **record, size_t *record_length, char record_id[72]);

/* Find a trusted record in a shared store and restore its blobs into a
 * separate current workspace before returning a hit. */
int tm_result_find_and_restore_in_store(
    int store_root_fd, int repository_root_fd,
    const char *command_fingerprint, const char *verification_fingerprint,
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
