#ifndef TM_KEY_H
#define TM_KEY_H

/* Create an Ed25519 private key at path and print its public trust material. */
int tm_key_generate(const char *path);

#endif
