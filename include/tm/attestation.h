#ifndef TM_ATTESTATION_H
#define TM_ATTESTATION_H

#include <stddef.h>

#include <openssl/evp.h>

#define TM_ED25519_SIGNATURE_SIZE 64

/* Sign "tm-result-v2\0" followed by canonical payload bytes. */
int tm_ed25519_sign(EVP_PKEY *private_key, const unsigned char *payload,
                    size_t payload_length,
                    unsigned char signature[TM_ED25519_SIGNATURE_SIZE]);

/* Verify exact payload bytes with an Ed25519 public key. */
int tm_ed25519_verify(EVP_PKEY *public_key, const unsigned char *payload,
                      size_t payload_length,
                      const unsigned char signature[TM_ED25519_SIGNATURE_SIZE]);

/* sha256: + lowercase SHA-256 of the raw 32-byte Ed25519 public key. */
int tm_ed25519_key_id(EVP_PKEY *public_key, char output[72]);

#endif
