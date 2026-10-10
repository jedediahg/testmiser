#include <stdio.h>
#include <string.h>

#include "tm/verification.h"

int main(void)
{
    const struct tm_input_observation inputs[] = {
        {"tests/missing", TM_INPUT_EXISTS, NULL, NULL, 0},
        {"tests/a", TM_INPUT_FILE,
         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         NULL, 0}
    };
    const struct tm_input_observation reordered[] = {inputs[1], inputs[0]};
    const struct tm_input_observation duplicates[] = {
        inputs[0], inputs[1], inputs[1]
    };
    const struct tm_input_observation conflicting[] = {
        inputs[0], inputs[1],
        {"tests/a", TM_INPUT_FILE,
         "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         NULL, 0}
    };
    const struct tm_input_observation invalid_path[] = {
        {"../outside", TM_INPUT_FILE,
         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         NULL, 0}
    };
    struct tm_verification_identity identity = {
        "sample",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "subdir",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        inputs, 2
    };
    const char *expected =
        "sha256:ba299d5d7bd04d93e635617e6d2e496248711a9fa93bf4360a98c706ad201622";
    const char *escaped_expected =
        "sha256:e9d0548651703103a7f80a977ed38e8f56f1eb0f405a0715af3ce6a1cf62dabc";
    char fingerprint[72];
    char reordered_fingerprint[72];

    if (tm_verification_fingerprint(&identity, fingerprint) != 0 ||
        strcmp(fingerprint, expected) != 0) {
        fprintf(stderr, "verification fingerprint golden vector failed\n");
        return 1;
    }
    identity.repository_id = "sample\nid";
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0 ||
        strcmp(reordered_fingerprint, escaped_expected) != 0) {
        fprintf(stderr, "verification JCS escaping vector failed\n");
        return 1;
    }
    identity.repository_id = "sample";
    identity.inputs = reordered;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0 ||
        strcmp(fingerprint, reordered_fingerprint) != 0) {
        fprintf(stderr, "input ordering changed verification identity\n");
        return 1;
    }
    identity.inputs = duplicates;
    identity.input_count = 3;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0 ||
        strcmp(fingerprint, reordered_fingerprint) != 0) {
        fprintf(stderr, "duplicate input changed verification identity\n");
        return 1;
    }
    identity.inputs = conflicting;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) == 0) {
        fprintf(stderr, "conflicting duplicate input was accepted\n");
        return 1;
    }
    identity.inputs = invalid_path;
    identity.input_count = 1;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) == 0) {
        fprintf(stderr, "path traversal entered verification identity\n");
        return 1;
    }
    identity.inputs = NULL;
    identity.input_count = 0;
    identity.working_directory = ".";
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0) {
        fprintf(stderr, "repository-root working directory was rejected\n");
        return 1;
    }
    return 0;
}
