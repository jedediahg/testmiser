#ifndef TM_KEY_H
#define TM_KEY_H

#include <openssl/evp.h>

/* Create an Ed25519 private key at path and print its public trust material. */
int tm_key_generate(const char *path);

/* Load an owner-only Ed25519 private key from a regular, non-symlink file. */
int tm_key_load_private(const char *path, EVP_PKEY **key);

#endif
