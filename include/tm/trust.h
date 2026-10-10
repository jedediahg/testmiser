#ifndef TM_TRUST_H
#define TM_TRUST_H

#include <stdint.h>

#include <openssl/evp.h>

struct tm_trust_policy;

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

#endif
