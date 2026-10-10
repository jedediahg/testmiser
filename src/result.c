#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "tm/attestation.h"
#include "tm/digest.h"
#include "tm/json.h"
#include "tm/input.h"
#include "tm/result.h"
#include "tm/trust.h"

static const unsigned char result_signature_domain[] = "tm-result-v2";

static int signature_message(const unsigned char *payload, size_t payload_size,
                             unsigned char **message, size_t *message_size)
{
    size_t domain_size = sizeof(result_signature_domain);
    if (payload_size > SIZE_MAX - domain_size) {
        errno = EOVERFLOW;
        return -1;
    }
    *message = malloc(domain_size + payload_size);
    if (*message == NULL) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(*message, result_signature_domain, domain_size);
    memcpy(*message + domain_size, payload, payload_size);
    *message_size = domain_size + payload_size;
    return 0;
}

static int object_put(struct tm_json_value *object, const char *key,
                      struct tm_json_value *value)
{
    if (value == NULL) return -1;
    if (tm_json_object_set(object, key, value) < 0) {
        tm_json_free(value);
        return -1;
    }
    return 0;
}

static struct tm_json_value *json_string(const char *value)
{
    return tm_json_new_string(value);
}

static const char *input_kind_name(enum tm_input_kind kind)
{
    switch (kind) {
    case TM_INPUT_DIRECTORY: return "directory";
    case TM_INPUT_EXISTS: return "exists";
    case TM_INPUT_FILE: return "file";
    case TM_INPUT_SYMLINK: return "symlink";
    }
    return NULL;
}

static int compare_input_pointers(const void *left, const void *right)
{
    const struct tm_input_observation *a =
        *(const struct tm_input_observation *const *)left;
    const struct tm_input_observation *b =
        *(const struct tm_input_observation *const *)right;
    int order = strcmp(a->path, b->path);
    if (order != 0) return order;
    return strcmp(input_kind_name(a->kind), input_kind_name(b->kind));
}

static struct tm_json_value *make_input(
    const struct tm_input_observation *input)
{
    struct tm_json_value *object = tm_json_new_object();
    const char *kind = input_kind_name(input->kind);

    if (object == NULL || kind == NULL ||
        object_put(object, "kind", json_string(kind)) < 0 ||
        object_put(object, "path", json_string(input->path)) < 0) {
        tm_json_free(object);
        return NULL;
    }
    switch (input->kind) {
    case TM_INPUT_FILE:
    case TM_INPUT_DIRECTORY:
        if (object_put(object, "sha256", json_string(input->digest)) < 0) {
            tm_json_free(object);
            return NULL;
        }
        break;
    case TM_INPUT_EXISTS:
        if (object_put(object, "state",
                       tm_json_new_boolean(input->exists)) < 0) {
            tm_json_free(object);
            return NULL;
        }
        break;
    case TM_INPUT_SYMLINK:
        if (object_put(object, "target", json_string(input->target)) < 0) {
            tm_json_free(object);
            return NULL;
        }
        break;
    }
    return object;
}

static struct tm_json_value *make_inputs(
    const struct tm_verification_identity *identity)
{
    struct tm_json_value *array = tm_json_new_array();
    const struct tm_input_observation **sorted;
    size_t index;

    if (array == NULL) return NULL;
    if (identity->input_count > SIZE_MAX / sizeof(*sorted)) {
        tm_json_free(array);
        errno = EOVERFLOW;
        return NULL;
    }
    sorted = identity->input_count == 0 ? NULL :
        malloc(identity->input_count * sizeof(*sorted));
    if (identity->input_count > 0 && sorted == NULL) {
        tm_json_free(array);
        errno = ENOMEM;
        return NULL;
    }
    for (index = 0; index < identity->input_count; index++) {
        sorted[index] = &identity->inputs[index];
    }
    if (identity->input_count > 1) {
        qsort(sorted, identity->input_count, sizeof(*sorted),
              compare_input_pointers);
    }
    for (index = 0; index < identity->input_count; index++) {
        struct tm_json_value *item;
        if (index > 0 && strcmp(sorted[index]->path,
                                sorted[index - 1]->path) == 0 &&
            sorted[index]->kind == sorted[index - 1]->kind) {
            continue;
        }
        item = make_input(sorted[index]);
        if (item == NULL || tm_json_array_append(array, item) < 0) {
            tm_json_free(item);
            free(sorted);
            tm_json_free(array);
            return NULL;
        }
    }
    free(sorted);
    return array;
}

static struct tm_json_value *make_payload(
    const struct tm_verification_identity *identity, uint64_t trust_epoch,
    const char *verification_fingerprint)
{
    struct tm_json_value *payload = tm_json_new_object();
    struct tm_json_value *environment = tm_json_new_object();
    struct tm_json_value *identity_json = tm_json_new_object();
    struct tm_json_value *result = tm_json_new_object();
    struct tm_json_value *inputs = NULL;
    struct tm_json_value *outputs = tm_json_new_array();

    if (payload == NULL || environment == NULL || identity_json == NULL ||
        result == NULL || outputs == NULL) goto fail;
    inputs = make_inputs(identity);
    if (inputs == NULL) goto fail;
    if (object_put(environment, "context_digest",
                   json_string(identity->context_digest)) < 0 ||
        object_put(environment, "profile_digest",
                   json_string(identity->profile_digest)) < 0 ||
        object_put(environment, "runtime_digest",
                   json_string(identity->runtime_digest)) < 0 ||
        object_put(identity_json, "command_fingerprint",
                   json_string(identity->command_fingerprint)) < 0 ||
        object_put(identity_json, "working_directory",
                   json_string(identity->working_directory)) < 0 ||
        object_put(result, "exit_code", tm_json_new_integer(0)) < 0 ||
        object_put(result, "signal", tm_json_new_null()) < 0) goto fail;
    if (object_put(payload, "environment", environment) < 0) {
        environment = NULL;
        goto fail;
    }
    environment = NULL;
    if (object_put(payload, "identity", identity_json) < 0) {
        identity_json = NULL;
        goto fail;
    }
    identity_json = NULL;
    if (object_put(payload, "inputs", inputs) < 0) {
        inputs = NULL;
        goto fail;
    }
    inputs = NULL;
    if (object_put(payload, "outputs", outputs) < 0) {
        outputs = NULL;
        goto fail;
    }
    outputs = NULL;
    if (object_put(payload, "repository_id",
                   json_string(identity->repository_id)) < 0) goto fail;
    if (object_put(payload, "result", result) < 0) {
        result = NULL;
        goto fail;
    }
    result = NULL;
    if (object_put(payload, "schema_version", tm_json_new_integer(2)) < 0 ||
        object_put(payload, "tm_semantics_version",
                   tm_json_new_integer(2)) < 0 ||
        object_put(payload, "trust_epoch",
                   tm_json_new_integer(trust_epoch)) < 0 ||
        object_put(payload, "verification_fingerprint",
                   json_string(verification_fingerprint)) < 0) {
        goto fail;
    }
    return payload;

fail:
    tm_json_free(environment);
    tm_json_free(identity_json);
    tm_json_free(result);
    tm_json_free(inputs);
    tm_json_free(outputs);
    tm_json_free(payload);
    return NULL;
}

static int format_sha256(const unsigned char *bytes, size_t length,
                         char output[72])
{
    char digest[65];
    if (tm_sha256_bytes(bytes, length, digest) < 0) return -1;
    memcpy(output, "sha256:", 7);
    memcpy(output + 7, digest, sizeof(digest));
    return 0;
}

int tm_result_create(const struct tm_verification_identity *identity,
                     uint64_t trust_epoch, EVP_PKEY *private_key,
                     unsigned char **record, size_t *record_length,
                     char record_id[72])
{
    struct tm_json_value *payload = NULL;
    struct tm_json_value *attestation = NULL;
    struct tm_json_value *envelope = NULL;
    unsigned char signature[TM_ED25519_SIGNATURE_SIZE];
    unsigned char signature_b64[EVP_ENCODE_LENGTH(TM_ED25519_SIGNATURE_SIZE)];
    unsigned char *payload_bytes = NULL;
    size_t payload_length = 0;
    unsigned char *message = NULL;
    size_t message_length = 0;
    unsigned char *envelope_bytes = NULL;
    size_t envelope_length = 0;
    unsigned char *record_with_lf = NULL;
    char verification_fingerprint[72];
    char key_id[72];
    int encoded_length;
    int result = -1;

    if (identity == NULL || private_key == NULL || record == NULL ||
        record_length == NULL || record_id == NULL ||
        trust_epoch > UINT64_C(9007199254740991)) {
        errno = EINVAL;
        return -1;
    }
    *record = NULL;
    *record_length = 0;
    if (tm_verification_fingerprint(identity, verification_fingerprint) < 0 ||
        tm_ed25519_key_id(private_key, key_id) < 0) goto done;
    payload = make_payload(identity, trust_epoch, verification_fingerprint);
    if (payload == NULL ||
        tm_json_canonicalize(payload, &payload_bytes, &payload_length) < 0 ||
        signature_message(payload_bytes, payload_length, &message,
                          &message_length) < 0 ||
        tm_ed25519_sign(private_key, message, message_length, signature) < 0)
        goto done;
    encoded_length = EVP_EncodeBlock(signature_b64, signature,
                                     TM_ED25519_SIGNATURE_SIZE);
    if (encoded_length != 88) { errno = EIO; goto done; }
    signature_b64[encoded_length] = '\0';
    attestation = tm_json_new_object();
    envelope = tm_json_new_object();
    if (attestation == NULL || envelope == NULL ||
        object_put(attestation, "algorithm", json_string("ed25519")) < 0 ||
        object_put(attestation, "key_id", json_string(key_id)) < 0 ||
        object_put(attestation, "signature",
                   json_string((const char *)signature_b64)) < 0) goto done;
    if (object_put(envelope, "attestation", attestation) < 0) {
        attestation = NULL;
        goto done;
    }
    attestation = NULL;
    if (object_put(envelope, "payload", payload) < 0) {
        payload = NULL;
        goto done;
    }
    payload = NULL;
    if (tm_json_canonicalize(envelope, &envelope_bytes, &envelope_length) < 0 ||
        envelope_length > SIZE_MAX - 2 ||
        format_sha256(envelope_bytes, envelope_length, record_id) < 0) {
        goto done;
    }
    record_with_lf = malloc(envelope_length + 2);
    if (record_with_lf == NULL) { errno = ENOMEM; goto done; }
    memcpy(record_with_lf, envelope_bytes, envelope_length);
    record_with_lf[envelope_length] = '\n';
    record_with_lf[envelope_length + 1] = '\0';
    *record = record_with_lf;
    *record_length = envelope_length + 1;
    record_with_lf = NULL;
    result = 0;

done:
    tm_json_free(payload);
    tm_json_free(attestation);
    tm_json_free(envelope);
    free(payload_bytes);
    free(message);
    free(envelope_bytes);
    free(record_with_lf);
    return result;
}

static int expect_object_size(const struct tm_json_value *value, size_t size)
{
    return tm_json_typeof(value) == TM_JSON_OBJECT &&
           tm_json_size(value) == size;
}

static const char *get_string(const struct tm_json_value *object,
                              const char *key)
{
    return tm_json_string_value(tm_json_object_get(object, key));
}

static int valid_sha256(const char *digest)
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

static int parse_inputs(const struct tm_json_value *array,
                        struct tm_input_observation **output,
                        size_t *output_count)
{
    size_t count;
    size_t index;
    struct tm_input_observation *inputs;

    if (tm_json_typeof(array) != TM_JSON_ARRAY) return -1;
    count = tm_json_size(array);
    if (count > SIZE_MAX / sizeof(*inputs)) return -1;
    inputs = count == 0 ? NULL : calloc(count, sizeof(*inputs));
    if (count > 0 && inputs == NULL) return -1;
    for (index = 0; index < count; index++) {
        const struct tm_json_value *item = tm_json_array_get(array, index);
        const char *kind;
        const char *path;
        if (tm_json_typeof(item) != TM_JSON_OBJECT) goto invalid;
        kind = get_string(item, "kind");
        path = get_string(item, "path");
        if (kind == NULL || path == NULL) goto invalid;
        inputs[index].path = path;
        if (strcmp(kind, "file") == 0 || strcmp(kind, "directory") == 0) {
            const char *digest = get_string(item, "sha256");
            if (!expect_object_size(item, 3) || digest == NULL) goto invalid;
            inputs[index].kind = strcmp(kind, "file") == 0 ?
                                 TM_INPUT_FILE : TM_INPUT_DIRECTORY;
            inputs[index].digest = digest;
        } else if (strcmp(kind, "exists") == 0) {
            const struct tm_json_value *state = tm_json_object_get(item, "state");
            if (!expect_object_size(item, 3) ||
                tm_json_typeof(state) != TM_JSON_BOOLEAN) goto invalid;
            inputs[index].kind = TM_INPUT_EXISTS;
            inputs[index].exists = tm_json_boolean_value(state);
        } else if (strcmp(kind, "symlink") == 0) {
            const char *target = get_string(item, "target");
            if (!expect_object_size(item, 3) || target == NULL) goto invalid;
            inputs[index].kind = TM_INPUT_SYMLINK;
            inputs[index].target = target;
        } else goto invalid;
    }
    *output = inputs;
    *output_count = count;
    return 0;

invalid:
    free(inputs);
    return -1;
}

static int canonical_input_order(const struct tm_input_observation *inputs,
                                 size_t count)
{
    size_t index;
    for (index = 1; index < count; index++) {
        int order = strcmp(inputs[index - 1].path, inputs[index].path);
        if (order == 0)
            order = strcmp(input_kind_name(inputs[index - 1].kind),
                           input_kind_name(inputs[index].kind));
        if (order >= 0) return 0;
    }
    return 1;
}

static int strict_base64_signature(const char *encoded,
                                   unsigned char signature[64])
{
    unsigned char decoded[EVP_DECODE_LENGTH(88)];
    unsigned char canonical[EVP_ENCODE_LENGTH(64)];
    int length;
    int canonical_length;
    size_t index;

    if (encoded == NULL || strlen(encoded) != 88 ||
        encoded[86] != '=' || encoded[87] != '=') return -1;
    for (index = 0; index < 86; index++) {
        unsigned char c = (unsigned char)encoded[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/')) return -1;
    }
    length = EVP_DecodeBlock(decoded, (const unsigned char *)encoded, 88);
    if (length != 66) return -1;
    memcpy(signature, decoded, 64);
    canonical_length = EVP_EncodeBlock(canonical, signature, 64);
    if (canonical_length != 88 || memcmp(canonical, encoded, 88) != 0) {
        return -1;
    }
    return 0;
}

void tm_result_summary_clear(struct tm_result_summary *summary)
{
    size_t i;
    if (summary == NULL) return;
    free(summary->repository_id);
    free(summary->profile_digest);
    free(summary->key_id);
    free(summary->verification_fingerprint);
    for (i = 0; i < summary->input_count; i++) {
        free((char *)summary->inputs[i].path);
        free((char *)summary->inputs[i].digest);
        free((char *)summary->inputs[i].target);
    }
    free(summary->inputs);
    memset(summary, 0, sizeof(*summary));
}

static char *copy_string(const char *value)
{
    if (value == NULL) return NULL;
    return strdup(value);
}

static int copy_input_manifest(const struct tm_input_observation *source,
                               size_t count,
                               struct tm_result_summary *summary)
{
    size_t i;
    if (count == 0) return 0;
    summary->inputs = calloc(count, sizeof(*summary->inputs));
    if (summary->inputs == NULL) return -1;
    summary->input_count = count;
    for (i = 0; i < count; i++) {
        summary->inputs[i] = source[i];
        summary->inputs[i].path = copy_string(source[i].path);
        summary->inputs[i].digest = copy_string(source[i].digest);
        summary->inputs[i].target = copy_string(source[i].target);
        if (summary->inputs[i].path == NULL ||
            (source[i].digest != NULL && summary->inputs[i].digest == NULL) ||
            (source[i].target != NULL && summary->inputs[i].target == NULL))
            return -1;
    }
    return 0;
}

int tm_result_inspect(const unsigned char *record, size_t record_length,
                      struct tm_result_summary *summary, char record_id[72])
{
    struct tm_json_value *envelope = NULL;
    struct tm_input_observation *inputs = NULL;
    size_t input_count = 0;
    const struct tm_json_value *payload;
    const struct tm_json_value *attestation;
    const struct tm_json_value *identity_json;
    const struct tm_json_value *environment;
    const struct tm_json_value *result_json;
    const struct tm_json_value *outputs;
    const char *repository_id;
    const char *profile_digest;
    const char *verification_fingerprint;
    const char *command_fingerprint;
    const char *working_directory;
    const char *runtime_digest;
    const char *context_digest;
    const char *key_id;
    unsigned char ignored_signature[64];
    unsigned char *canonical_envelope = NULL;
    size_t canonical_envelope_length = 0;
    uint64_t trust_epoch;
    uint64_t semantics_version;
    struct tm_verification_identity identity;
    char actual_fingerprint[72];
    int status = -1;

    if (record == NULL || record_length < 2 || record[record_length - 1] != '\n' ||
        summary == NULL || record_id == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(summary, 0, sizeof(*summary));
    if (tm_json_parse(record, record_length - 1, &envelope) < 0 ||
        tm_json_canonicalize(envelope, &canonical_envelope,
                             &canonical_envelope_length) < 0 ||
        canonical_envelope_length != record_length - 1 ||
        memcmp(canonical_envelope, record, canonical_envelope_length) != 0 ||
        !expect_object_size(envelope, 2)) goto invalid;
    payload = tm_json_object_get(envelope, "payload");
    attestation = tm_json_object_get(envelope, "attestation");
    if (!expect_object_size(payload, 10) ||
        !expect_object_size(attestation, 3) ||
        tm_json_integer_value(tm_json_object_get(payload, "schema_version")) != 2 ||
        tm_json_integer_value(tm_json_object_get(payload,
                                                "tm_semantics_version")) != 2)
        goto invalid;
    repository_id = get_string(payload, "repository_id");
    profile_digest = get_string(
        tm_json_object_get(payload, "environment"), "profile_digest");
    verification_fingerprint = get_string(payload, "verification_fingerprint");
    identity_json = tm_json_object_get(payload, "identity");
    environment = tm_json_object_get(payload, "environment");
    outputs = tm_json_object_get(payload, "outputs");
    result_json = tm_json_object_get(payload, "result");
    if (repository_id == NULL || profile_digest == NULL ||
        verification_fingerprint == NULL || !expect_object_size(identity_json, 2) ||
        !expect_object_size(environment, 3) || !expect_object_size(result_json, 2) ||
        tm_json_typeof(outputs) != TM_JSON_ARRAY || tm_json_size(outputs) != 0 ||
        tm_json_integer_value(tm_json_object_get(result_json, "exit_code")) != 0 ||
        tm_json_object_get(result_json, "signal") == NULL ||
        tm_json_typeof(tm_json_object_get(result_json, "signal")) != TM_JSON_NULL)
        goto invalid;
    trust_epoch = tm_json_integer_value(tm_json_object_get(payload, "trust_epoch"));
    semantics_version = tm_json_integer_value(
        tm_json_object_get(payload, "tm_semantics_version"));
    if (trust_epoch == UINT64_MAX || semantics_version == UINT64_MAX) goto invalid;
    command_fingerprint = get_string(identity_json, "command_fingerprint");
    working_directory = get_string(identity_json, "working_directory");
    runtime_digest = get_string(environment, "runtime_digest");
    context_digest = get_string(environment, "context_digest");
    if (command_fingerprint == NULL || working_directory == NULL ||
        runtime_digest == NULL || context_digest == NULL ||
        parse_inputs(tm_json_object_get(payload, "inputs"), &inputs,
                     &input_count) < 0 ||
        !canonical_input_order(inputs, input_count)) goto invalid;
    identity = (struct tm_verification_identity){
        repository_id, command_fingerprint, working_directory, profile_digest,
        runtime_digest, context_digest, inputs, input_count
    };
    if (tm_verification_fingerprint(&identity, actual_fingerprint) < 0 ||
        strcmp(actual_fingerprint, verification_fingerprint) != 0 ||
        strlen(command_fingerprint) != 71 ||
        strlen(verification_fingerprint) != 71) goto invalid;
    if (get_string(attestation, "algorithm") == NULL ||
        strcmp(get_string(attestation, "algorithm"), "ed25519") != 0 ||
        !valid_sha256(get_string(attestation, "key_id")) ||
        strict_base64_signature(get_string(attestation, "signature"),
                                ignored_signature) < 0) goto invalid;
    key_id = get_string(attestation, "key_id");
    summary->repository_id = copy_string(repository_id);
    summary->profile_digest = copy_string(profile_digest);
    summary->key_id = copy_string(key_id);
    summary->verification_fingerprint = copy_string(verification_fingerprint);
    if (summary->repository_id == NULL || summary->profile_digest == NULL ||
        summary->key_id == NULL || summary->verification_fingerprint == NULL) {
        errno = ENOMEM;
        goto done;
    }
    if (copy_input_manifest(inputs, input_count, summary) < 0) {
        errno = ENOMEM;
        goto done;
    }
    memcpy(summary->command_id, command_fingerprint + 7, 64);
    summary->command_id[64] = '\0';
    memcpy(summary->verification_id, verification_fingerprint + 7, 64);
    summary->verification_id[64] = '\0';
    summary->trust_epoch = trust_epoch;
    summary->semantics_version = semantics_version;
    if (format_sha256(canonical_envelope, canonical_envelope_length,
                      record_id) < 0) goto done;
    status = 0;
    goto done;

invalid:
    errno = EBADMSG;

done:
    if (status != 0) tm_result_summary_clear(summary);
    tm_json_free(envelope);
    free(inputs);
    free(canonical_envelope);
    return status;
}

int tm_result_verify_inputs_match(
    const unsigned char *record, size_t record_length,
    const struct tm_trust_policy *trust_policy, int repository_root_fd,
    char record_id[72])
{
    struct tm_result_summary summary = {0};
    size_t i;
    int status = -1;
    if (repository_root_fd < 0 || trust_policy == NULL || record_id == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (tm_result_inspect(record, record_length, &summary, record_id) < 0)
        return -1;
    if (tm_result_verify_trusted(record, record_length, trust_policy,
                                 summary.verification_fingerprint,
                                 record_id) < 0) goto done;
    for (i = 0; i < summary.input_count; i++) {
        int match = tm_input_matches(repository_root_fd, &summary.inputs[i]);
        if (match != 0) {
            status = match;
            goto done;
        }
    }
    status = 0;
done:
    tm_result_summary_clear(&summary);
    return status;
}

int tm_result_verify(const unsigned char *record, size_t record_length,
                     EVP_PKEY *trusted_public_key,
                     const struct tm_result_policy *policy,
                     char record_id[72])
{
    struct tm_json_value *envelope = NULL;
    struct tm_input_observation *inputs = NULL;
    size_t input_count = 0;
    const struct tm_json_value *payload;
    const struct tm_json_value *attestation;
    const struct tm_json_value *identity_json;
    const struct tm_json_value *environment;
    const struct tm_json_value *result_json;
    const struct tm_json_value *outputs;
    const char *repository_id;
    const char *profile_digest;
    const char *verification_fingerprint;
    const char *command_fingerprint;
    const char *working_directory;
    const char *runtime_digest;
    const char *context_digest;
    const char *key_id;
    const char *encoded_signature;
    uint64_t trust_epoch;
    struct tm_verification_identity identity;
    unsigned char signature[64];
    unsigned char *canonical_envelope = NULL;
    size_t canonical_envelope_length = 0;
    unsigned char *canonical_payload = NULL;
    size_t canonical_payload_length = 0;
    unsigned char *message = NULL;
    size_t message_length = 0;
    char actual_key_id[72];
    char actual_verification_fingerprint[72];
    int result = -1;

    if (record == NULL || record_length < 2 || record[record_length - 1] != '\n' ||
        trusted_public_key == NULL || policy == NULL || record_id == NULL ||
        policy->repository_id == NULL ||
        policy->approved_profile_digest == NULL ||
        policy->expected_verification_fingerprint == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (tm_json_parse(record, record_length - 1, &envelope) < 0 ||
        tm_json_canonicalize(envelope, &canonical_envelope,
                             &canonical_envelope_length) < 0 ||
        canonical_envelope_length != record_length - 1 ||
        memcmp(canonical_envelope, record, canonical_envelope_length) != 0 ||
        !expect_object_size(envelope, 2)) {
        errno = EBADMSG;
        goto done;
    }
    payload = tm_json_object_get(envelope, "payload");
    attestation = tm_json_object_get(envelope, "attestation");
    if (!expect_object_size(payload, 10) ||
        !expect_object_size(attestation, 3)) {
        errno = EBADMSG;
        goto done;
    }
    if (tm_json_integer_value(tm_json_object_get(payload, "schema_version")) != 2 ||
        tm_json_integer_value(tm_json_object_get(payload,
                                                "tm_semantics_version")) != 2) {
        errno = EPROTONOSUPPORT;
        goto done;
    }
    repository_id = get_string(payload, "repository_id");
    verification_fingerprint = get_string(payload,
                                           "verification_fingerprint");
    if (repository_id == NULL ||
        strcmp(repository_id, policy->repository_id) != 0) {
        errno = EACCES;
        goto done;
    }
    trust_epoch = tm_json_integer_value(
        tm_json_object_get(payload, "trust_epoch"));
    if (trust_epoch == UINT64_MAX || trust_epoch < policy->minimum_trust_epoch) {
        errno = EACCES;
        goto done;
    }
    identity_json = tm_json_object_get(payload, "identity");
    environment = tm_json_object_get(payload, "environment");
    outputs = tm_json_object_get(payload, "outputs");
    result_json = tm_json_object_get(payload, "result");
    if (!expect_object_size(identity_json, 2) ||
        !expect_object_size(environment, 3) ||
        !expect_object_size(result_json, 2) ||
        tm_json_typeof(outputs) != TM_JSON_ARRAY || tm_json_size(outputs) != 0 ||
        tm_json_integer_value(tm_json_object_get(result_json, "exit_code")) != 0 ||
        tm_json_object_get(result_json, "signal") == NULL ||
        tm_json_typeof(tm_json_object_get(result_json, "signal")) != TM_JSON_NULL) {
        errno = EBADMSG;
        goto done;
    }
    command_fingerprint = get_string(identity_json, "command_fingerprint");
    working_directory = get_string(identity_json, "working_directory");
    profile_digest = get_string(environment, "profile_digest");
    runtime_digest = get_string(environment, "runtime_digest");
    context_digest = get_string(environment, "context_digest");
    if (command_fingerprint == NULL || working_directory == NULL ||
        profile_digest == NULL || runtime_digest == NULL ||
        context_digest == NULL || verification_fingerprint == NULL ||
        strcmp(profile_digest, policy->approved_profile_digest) != 0) {
        errno = EACCES;
        goto done;
    }
    if (parse_inputs(tm_json_object_get(payload, "inputs"), &inputs,
                     &input_count) < 0 ||
        !canonical_input_order(inputs, input_count)) {
        errno = EBADMSG;
        goto done;
    }
    identity = (struct tm_verification_identity){
        repository_id, command_fingerprint, working_directory, profile_digest,
        runtime_digest, context_digest, inputs, input_count
    };
    if (tm_verification_fingerprint(&identity,
                                    actual_verification_fingerprint) < 0 ||
        strcmp(actual_verification_fingerprint, verification_fingerprint) != 0 ||
        strcmp(actual_verification_fingerprint,
               policy->expected_verification_fingerprint) != 0) {
        errno = EACCES;
        goto done;
    }
    if (get_string(attestation, "algorithm") == NULL ||
        strcmp(get_string(attestation, "algorithm"), "ed25519") != 0) {
        errno = EPROTONOSUPPORT;
        goto done;
    }
    key_id = get_string(attestation, "key_id");
    encoded_signature = get_string(attestation, "signature");
    if (tm_ed25519_key_id(trusted_public_key, actual_key_id) < 0 ||
        key_id == NULL || strcmp(key_id, actual_key_id) != 0 ||
        strict_base64_signature(encoded_signature, signature) < 0) {
        errno = EACCES;
        goto done;
    }
    if (tm_json_canonicalize(payload, &canonical_payload,
                             &canonical_payload_length) < 0 ||
        signature_message(canonical_payload, canonical_payload_length,
                          &message, &message_length) < 0 ||
        tm_ed25519_verify(trusted_public_key, message, message_length,
                          signature) < 0) {
        errno = EKEYREJECTED;
        goto done;
    }
    if (format_sha256(canonical_envelope, canonical_envelope_length,
                      record_id) < 0) goto done;
    result = 0;

done:
    tm_json_free(envelope);
    free(inputs);
    free(canonical_envelope);
    free(canonical_payload);
    free(message);
    return result;
}

int tm_result_verify_trusted(const unsigned char *record, size_t record_length,
                             const struct tm_trust_policy *trust_policy,
                             const char *expected_verification_fingerprint,
                             char record_id[72])
{
    struct tm_json_value *document = NULL;
    const struct tm_json_value *payload;
    const struct tm_json_value *environment;
    const struct tm_json_value *attestation;
    const struct tm_json_value *epoch_json;
    const struct tm_json_value *semantics_json;
    const char *repository_id;
    const char *profile_digest;
    const char *key_id;
    uint64_t trust_epoch;
    uint64_t semantics_version;
    EVP_PKEY *public_key = NULL;
    struct tm_result_policy expected;
    int result = -1;

    if (record == NULL || record_length < 2 || record[record_length - 1] != '\n' ||
        trust_policy == NULL || expected_verification_fingerprint == NULL ||
        record_id == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (tm_json_parse(record, record_length - 1, &document) < 0) goto done;
    payload = tm_json_object_get(document, "payload");
    attestation = tm_json_object_get(document, "attestation");
    environment = tm_json_object_get(payload, "environment");
    repository_id = get_string(payload, "repository_id");
    profile_digest = get_string(environment, "profile_digest");
    key_id = get_string(attestation, "key_id");
    epoch_json = tm_json_object_get(payload, "trust_epoch");
    semantics_json = tm_json_object_get(payload, "tm_semantics_version");
    trust_epoch = tm_json_integer_value(epoch_json);
    semantics_version = tm_json_integer_value(semantics_json);
    if (repository_id == NULL || profile_digest == NULL || key_id == NULL ||
        trust_epoch == UINT64_MAX || semantics_version == UINT64_MAX ||
        tm_trust_policy_authorize(trust_policy, repository_id, profile_digest,
                                  key_id, trust_epoch, semantics_version,
                                  &public_key) < 0) goto done;
    expected = (struct tm_result_policy){
        repository_id, profile_digest, 0, expected_verification_fingerprint
    };
    result = tm_result_verify(record, record_length, public_key, &expected,
                              record_id);

done:
    tm_json_free(document);
    EVP_PKEY_free(public_key);
    return result;
}
