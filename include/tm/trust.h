#ifndef TM_TRUST_H
#define TM_TRUST_H

#include <stdint.h>

#include <openssl/evp.h>

struct tm_trust_policy;

enum tm_trust_status {
    TM_TRUST_APPROVED,
    TM_TRUST_REVOKED,
    TM_TRUST_UNKNOWN_REPOSITORY,
    TM_TRUST_UNKNOWN_KEY,
    TM_TRUST_UNAPPROVED_PROFILE,
    TM_TRUST_STALE_EPOCH,
    TM_TRUST_UNSUPPORTED_SEMANTICS,
    TM_TRUST_POLICY_ERROR
};

/* Load a bounded operator-managed JSON policy from a protected regular file. */
int tm_trust_policy_load(const char *path, struct tm_trust_policy **output);
void tm_trust_policy_free(struct tm_trust_policy *policy);

/* Resolve only explicitly approved repository/profile/key/epoch/semantics. */
int tm_trust_policy_authorize(const struct tm_trust_policy *policy,
                              const char *repository_id,
                              const char *profile_digest,
                              const char *key_id,
                              uint64_t trust_epoch,
                              uint64_t semantics_version,
                              EVP_PKEY **public_key);

/* Classify a claim and return its public key when that key is provisioned,
 * even if the profile or epoch is no longer approved. */
enum tm_trust_status tm_trust_policy_classify(
    const struct tm_trust_policy *policy, const char *repository_id,
    const char *profile_digest, const char *key_id, uint64_t trust_epoch,
    uint64_t semantics_version, EVP_PKEY **public_key);

#endif
