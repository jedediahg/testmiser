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
    const struct tm_input_observation directory_input[] = {
        {"tests/data", TM_INPUT_DIRECTORY,
         "sha256:4444444444444444444444444444444444444444444444444444444444444444",
         NULL, 0}
    };
    const struct tm_input_observation existing_input[] = {
        {"tests/generated", TM_INPUT_EXISTS, NULL, NULL, 1}
    };
    const struct tm_input_observation symlink_input[] = {
        {"tests/current", TM_INPUT_SYMLINK, NULL, "data/v1", 0}
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
    identity.working_directory = "subdir";
    identity.inputs = directory_input;
    identity.input_count = 1;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0 ||
        strcmp(reordered_fingerprint,
            "sha256:4fcbdd8fd30fbf482882e4bac640fb1ebc66381ea273a5ed342c6cb470bcf892") != 0) {
        fprintf(stderr, "directory input golden vector failed\n");
        return 1;
    }
    identity.inputs = existing_input;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0 ||
        strcmp(reordered_fingerprint,
            "sha256:b92788dd98e7b0bdc412a483a1547eba442496ddccf0eb85e6914a5f35263541") != 0) {
        fprintf(stderr, "present-path input golden vector failed\n");
        return 1;
    }
    identity.inputs = symlink_input;
    if (tm_verification_fingerprint(&identity, reordered_fingerprint) != 0 ||
        strcmp(reordered_fingerprint,
            "sha256:d543e46c387b8cd45e245b167f26c78dff5269e6b3a7d4559b8a4707c5763d66") != 0) {
        fprintf(stderr, "symlink input golden vector failed\n");
        return 1;
    }
    return 0;
}
