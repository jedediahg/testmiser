#define _POSIX_C_SOURCE 200809L

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/key.h"

int main(void)
{
    char directory[] = "/tmp/tm-key-test-XXXXXX";
    char path[256] = {0}, link_path[256] = {0};
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *generated = NULL, *loaded = NULL;
    FILE *stream = NULL;
    int result = 1;

    if (mkdtemp(directory) == NULL ||
        snprintf(path, sizeof(path), "%s/private.pem", directory) >=
            (int)sizeof(path) ||
        snprintf(link_path, sizeof(link_path), "%s/link.pem", directory) >=
            (int)sizeof(link_path)) goto done;
    context = EVP_PKEY_CTX_new_from_name(NULL, "ED25519", NULL);
    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_generate(context, &generated) <= 0) goto done;
    stream = fopen(path, "w");
    if (stream == NULL) goto done;
    if (PEM_write_PrivateKey(stream, generated, NULL, NULL, 0, NULL, NULL) != 1)
        goto done;
    if (fclose(stream) != 0) { stream = NULL; goto done; }
    stream = NULL;
    if (chmod(path, 0600) < 0 || tm_key_load_private(path, &loaded) < 0 ||
        EVP_PKEY_is_a(loaded, "ED25519") != 1) goto done;
    EVP_PKEY_free(loaded);
    loaded = NULL;
    if (chmod(path, 0640) < 0 || tm_key_load_private(path, &loaded) == 0)
        goto done;
    if (chmod(path, 0600) < 0 || symlink(path, link_path) < 0 ||
        tm_key_load_private(link_path, &loaded) == 0) goto done;
    result = 0;
done:
    if (stream != NULL) fclose(stream);
    EVP_PKEY_free(loaded);
    EVP_PKEY_free(generated);
    EVP_PKEY_CTX_free(context);
    if (link_path[0] != '\0') unlink(link_path);
    if (path[0] != '\0') unlink(path);
    rmdir(directory);
    if (result != 0) fprintf(stderr, "key loading test failed\n");
    return result;
}
