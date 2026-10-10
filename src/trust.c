#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "tm/attestation.h"
#include "tm/json.h"
#include "tm/trust.h"

#define TRUST_POLICY_LIMIT (1024U * 1024U)
#define TRUST_POLICY_MAX_ENTRIES 4096U

struct tm_trust_policy {
    struct tm_json_value *document;
};

static const struct tm_json_value *field(const struct tm_json_value *object,
                                         const char *name)
{
    return tm_json_object_get(object, name);
}

static const char *string_field(const struct tm_json_value *object,
                                const char *name)
{
    return tm_json_string_value(field(object, name));
}

static int object_size(const struct tm_json_value *value, size_t expected)
{
    return tm_json_typeof(value) == TM_JSON_OBJECT &&
           tm_json_size(value) == expected;
}

static int valid_digest(const char *digest)
{
    size_t index;
    if (digest == NULL || strlen(digest) != 71 ||
        memcmp(digest, "sha256:", 7) != 0) return 0;
    for (index = 7; index < 71; index++) {
        if (!((digest[index] >= '0' && digest[index] <= '9') ||
              (digest[index] >= 'a' && digest[index] <= 'f'))) return 0;
    }
    return 1;
}

static int unique_string_array(const struct tm_json_value *array,
                               int require_digest)
{
    size_t index;
    size_t other;
    if (tm_json_typeof(array) != TM_JSON_ARRAY ||
        tm_json_size(array) > TRUST_POLICY_MAX_ENTRIES) return 0;
    for (index = 0; index < tm_json_size(array); index++) {
        const char *value = tm_json_string_value(tm_json_array_get(array, index));
        if (value == NULL || value[0] == '\0' ||
            (require_digest && !valid_digest(value))) return 0;
        for (other = 0; other < index; other++) {
            const char *previous =
                tm_json_string_value(tm_json_array_get(array, other));
            if (previous != NULL && strcmp(previous, value) == 0) return 0;
        }
    }
    return 1;
}

static int decode_public_key(const char *encoded, EVP_PKEY **output)
{
    unsigned char decoded[EVP_DECODE_LENGTH(44)];
    unsigned char canonical[EVP_ENCODE_LENGTH(32)];
    int decoded_length;
    int encoded_length;
    EVP_PKEY *key;

    if (encoded == NULL || strlen(encoded) != 44 || encoded[43] != '=') {
        return -1;
    }
    decoded_length = EVP_DecodeBlock(decoded,
                                    (const unsigned char *)encoded, 44);
    if (decoded_length != 33) return -1;
    encoded_length = EVP_EncodeBlock(canonical, decoded, 32);
    if (encoded_length != 44 || memcmp(canonical, encoded, 44) != 0) return -1;
    key = EVP_PKEY_new_raw_public_key_ex(NULL, "ED25519", NULL, decoded, 32);
    if (key == NULL) return -1;
    *output = key;
    return 0;
}

static int valid_role(const char *role)
{
    size_t index;
    size_t length;
    if (role == NULL || (length = strlen(role)) == 0 || length > 32) return 0;
    for (index = 0; index < length; index++) {
        unsigned char c = (unsigned char)role[index];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_')) return 0;
    }
    return 1;
}

static int validate_keys(const struct tm_json_value *keys)
{
    size_t index;
    size_t other;
    if (tm_json_typeof(keys) != TM_JSON_ARRAY ||
        tm_json_size(keys) > TRUST_POLICY_MAX_ENTRIES) return 0;
    for (index = 0; index < tm_json_size(keys); index++) {
        const struct tm_json_value *item = tm_json_array_get(keys, index);
        const char *key_id;
        const char *public_key_text;
        const char *role;
        EVP_PKEY *public_key = NULL;
        char actual_key_id[72];
        int valid;

        if (!object_size(item, 3)) return 0;
        key_id = string_field(item, "key_id");
        public_key_text = string_field(item, "public_key");
        role = string_field(item, "role");
        if (!valid_digest(key_id) || !valid_role(role) ||
            decode_public_key(public_key_text, &public_key) < 0) return 0;
        valid = tm_ed25519_key_id(public_key, actual_key_id) == 0 &&
                strcmp(key_id, actual_key_id) == 0;
        EVP_PKEY_free(public_key);
        if (!valid) return 0;
        for (other = 0; other < index; other++) {
            const struct tm_json_value *previous = tm_json_array_get(keys, other);
            const char *previous_id = string_field(previous, "key_id");
            if (previous_id != NULL && strcmp(previous_id, key_id) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

static int validate_repositories(const struct tm_json_value *repositories)
{
    size_t index;
    size_t other;

    if (tm_json_typeof(repositories) != TM_JSON_ARRAY ||
        tm_json_size(repositories) == 0 ||
        tm_json_size(repositories) > TRUST_POLICY_MAX_ENTRIES) return 0;
    for (index = 0; index < tm_json_size(repositories); index++) {
        const struct tm_json_value *repository =
            tm_json_array_get(repositories, index);
        const char *repository_id;
        const struct tm_json_value *minimum;
        const struct tm_json_value *semantics;
        const struct tm_json_value *profiles;
        const struct tm_json_value *keys;
        const struct tm_json_value *revoked;
        size_t version_index;

        if (!object_size(repository, 6)) return 0;
        repository_id = string_field(repository, "repository_id");
        minimum = field(repository, "minimum_trust_epoch");
        semantics = field(repository, "allowed_semantics");
        profiles = field(repository, "profiles");
        keys = field(repository, "keys");
        revoked = field(repository, "revoked_key_ids");
        if (repository_id == NULL || repository_id[0] == '\0' ||
            tm_json_typeof(minimum) != TM_JSON_INTEGER ||
            tm_json_typeof(semantics) != TM_JSON_ARRAY ||
            tm_json_size(semantics) == 0 ||
            !unique_string_array(profiles, 1) ||
            !validate_keys(keys) || !unique_string_array(revoked, 1)) return 0;
        for (version_index = 0; version_index < tm_json_size(semantics);
             version_index++) {
            uint64_t version = tm_json_integer_value(
                tm_json_array_get(semantics, version_index));
            size_t prior;
            if (version == UINT64_MAX || version == 0) return 0;
            for (prior = 0; prior < version_index; prior++) {
                if (tm_json_integer_value(
                        tm_json_array_get(semantics, prior)) == version) return 0;
            }
        }
        for (other = 0; other < index; other++) {
            const char *previous_id = string_field(
                tm_json_array_get(repositories, other), "repository_id");
            if (previous_id != NULL &&
                strcmp(previous_id, repository_id) == 0) return 0;
        }
    }
    return 1;
}

static int stat_unchanged(const struct stat *before, const struct stat *after)
{
    return before->st_dev == after->st_dev && before->st_ino == after->st_ino &&
           before->st_size == after->st_size &&
           before->st_mtim.tv_sec == after->st_mtim.tv_sec &&
           before->st_mtim.tv_nsec == after->st_mtim.tv_nsec &&
           before->st_ctim.tv_sec == after->st_ctim.tv_sec &&
           before->st_ctim.tv_nsec == after->st_ctim.tv_nsec;
}

static int read_policy_file(const char *path, unsigned char **output,
                            size_t *length)
{
    struct stat before;
    struct stat after;
    unsigned char *data;
    size_t used = 0;
    int descriptor;
    int saved_errno;

    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    if (fstat(descriptor, &before) < 0 || !S_ISREG(before.st_mode) ||
        (before.st_mode & 022) != 0 ||
        (before.st_uid != geteuid() && before.st_uid != 0) ||
        before.st_size < 2 || (uint64_t)before.st_size > TRUST_POLICY_LIMIT) {
        close(descriptor);
        errno = EACCES;
        return -1;
    }
    data = malloc(TRUST_POLICY_LIMIT + 1);
    if (data == NULL) {
        close(descriptor);
        errno = ENOMEM;
        return -1;
    }
    while (used < TRUST_POLICY_LIMIT) {
        ssize_t count = read(descriptor, data + used, TRUST_POLICY_LIMIT - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) goto fail;
        if (count == 0) break;
        used += (size_t)count;
    }
    if (used == TRUST_POLICY_LIMIT) {
        unsigned char extra;
        ssize_t count = read(descriptor, &extra, 1);
        if (count != 0) { errno = EFBIG; goto fail; }
    }
    if (fstat(descriptor, &after) < 0 || !stat_unchanged(&before, &after) ||
        used != (size_t)before.st_size) {
        errno = EBUSY;
        goto fail;
    }
    close(descriptor);
    *output = data;
    *length = used;
    return 0;

fail:
    saved_errno = errno;
    close(descriptor);
    free(data);
    errno = saved_errno;
    return -1;
}

int tm_trust_policy_load(const char *path, struct tm_trust_policy **output)
{
    unsigned char *data = NULL;
    size_t length = 0;
    struct tm_trust_policy *policy = NULL;
    const struct tm_json_value *version;
    const struct tm_json_value *repositories;
    int result = -1;

    if (path == NULL || output == NULL) { errno = EINVAL; return -1; }
    *output = NULL;
    if (read_policy_file(path, &data, &length) < 0) return -1;
    policy = calloc(1, sizeof(*policy));
    if (policy == NULL) { errno = ENOMEM; goto done; }
    if (tm_json_parse(data, length, &policy->document) < 0 ||
        !object_size(policy->document, 2)) {
        errno = EBADMSG;
        goto done;
    }
    version = field(policy->document, "schema_version");
    repositories = field(policy->document, "repositories");
    if (tm_json_integer_value(version) != 1 ||
        !validate_repositories(repositories)) {
        errno = EBADMSG;
        goto done;
    }
    result = 0;
    *output = policy;
    policy = NULL;

done:
    tm_trust_policy_free(policy);
    free(data);
    return result;
}

void tm_trust_policy_free(struct tm_trust_policy *policy)
{
    if (policy == NULL) return;
    tm_json_free(policy->document);
    free(policy);
}

static int array_contains_string(const struct tm_json_value *array,
                                 const char *needle)
{
    size_t index;
    for (index = 0; index < tm_json_size(array); index++) {
        const char *candidate = tm_json_string_value(
            tm_json_array_get(array, index));
        if (candidate != NULL && strcmp(candidate, needle) == 0) return 1;
    }
    return 0;
}

int tm_trust_policy_authorize(const struct tm_trust_policy *policy,
                             const char *repository_id,
                             const char *profile_digest,
                             const char *key_id,
                             uint64_t trust_epoch,
                             uint64_t semantics_version,
                             EVP_PKEY **public_key)
{
    const struct tm_json_value *repositories;
    size_t index;

    if (policy == NULL || repository_id == NULL ||
        !valid_digest(profile_digest) || !valid_digest(key_id) ||
        public_key == NULL) {
        errno = EINVAL;
        return -1;
    }
    *public_key = NULL;
    repositories = field(policy->document, "repositories");
    for (index = 0; index < tm_json_size(repositories); index++) {
        const struct tm_json_value *repository =
            tm_json_array_get(repositories, index);
        const char *candidate_id = string_field(repository, "repository_id");
        const struct tm_json_value *minimum =
            field(repository, "minimum_trust_epoch");
        const struct tm_json_value *semantics =
            field(repository, "allowed_semantics");
        const struct tm_json_value *profiles = field(repository, "profiles");
        const struct tm_json_value *keys = field(repository, "keys");
        const struct tm_json_value *revoked =
            field(repository, "revoked_key_ids");
        size_t key_index;
        int semantics_allowed = 0;

        if (candidate_id == NULL || strcmp(candidate_id, repository_id) != 0)
            continue;
        if (trust_epoch < tm_json_integer_value(minimum) ||
            !array_contains_string(profiles, profile_digest) ||
            array_contains_string(revoked, key_id)) {
            errno = EACCES;
            return -1;
        }
        for (key_index = 0; key_index < tm_json_size(semantics); key_index++) {
            if (tm_json_integer_value(tm_json_array_get(semantics, key_index)) ==
                semantics_version) semantics_allowed = 1;
        }
        if (!semantics_allowed) { errno = EACCES; return -1; }
        for (key_index = 0; key_index < tm_json_size(keys); key_index++) {
            const struct tm_json_value *key = tm_json_array_get(keys, key_index);
            const char *candidate_key_id = string_field(key, "key_id");
            const char *public_key_text = string_field(key, "public_key");
            if (candidate_key_id != NULL &&
                strcmp(candidate_key_id, key_id) == 0) {
                if (decode_public_key(public_key_text, public_key) < 0) {
                    errno = EBADMSG;
                    return -1;
                }
                return 0;
            }
        }
        errno = EACCES;
        return -1;
    }
    errno = EACCES;
    return -1;
}
