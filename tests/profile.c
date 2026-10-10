#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tm/profile.h"

static int save(const char *path, const char *json)
{
    size_t size = strlen(json), offset = 0;
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return -1;
    while (offset < size) {
        ssize_t n = write(fd, json + offset, size - offset);
        if (n < 0) { close(fd); return -1; }
        offset += (size_t)n;
    }
    return close(fd);
}

int main(void)
{
    static const char valid[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{\"LANG\":\"C\"},"
        "\"input_roots\":[\"src\",\"tests\"],\"output_roots\":[],"
        "\"scratch_roots\":[\"/tmp\"]}";
    static const char unsafe[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"../outside\"],\"output_roots\":[],"
        "\"scratch_roots\":[\"/tmp\"]}";
    static const char overlap[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"tests\"],\"output_roots\":[\"tests/report\"],"
        "\"scratch_roots\":[\"/tmp\"]}";
    static const char metadata_input[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\".tm/results\"],\"output_roots\":[],"
        "\"scratch_roots\":[\"/tmp\"]}";
    static const char metadata_output[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[],\"output_roots\":[\".tm\"],"
        "\"scratch_roots\":[\"/tmp\"]}";
    static const char metadata_scratch[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[],\"output_roots\":[],"
        "\"scratch_roots\":[\"/workspace/.tm/scratch\"]}";
    static const char nondeterministic[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":false,"
        "\"privacy_class\":\"secret-dependent\",\"environment\":{},"
        "\"input_roots\":[],\"output_roots\":[],\"scratch_roots\":[]}";
    static const char output_profile[] =
        "{\"schema_version\":1,\"repository_id\":\"sample\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v1\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"src\"],\"output_roots\":[\"build\"],"
        "\"scratch_roots\":[\"/tmp\"]}";
    struct tm_profile *profile = NULL;
    char path[] = "/tmp/tm-profile-test-XXXXXX";
    char valid_v2[sizeof(valid)];
    char digest[72];
    char *backend_name;
    int fd = mkstemp(path), status = 1;
    if (fd < 0) return 1;
    close(fd);
    if (save(path, valid) < 0 || tm_profile_load(path, &profile) < 0 ||
        strcmp(tm_profile_repository_id(profile), "sample") != 0 ||
        strlen(tm_profile_digest(profile)) != 71 ||
        strcmp(tm_profile_digest(profile),
          "sha256:9594caa6d198b87e03b0dbfd5a869f6096ad69f889dd06bf10b8094cabb716dc") != 0)
        goto done;
    if (!tm_profile_allows_input_path(profile, "src/main.c") ||
        tm_profile_input_root_count(profile) != 2 ||
        strcmp(tm_profile_input_root(profile, 0), "src") != 0 ||
        strcmp(tm_profile_input_root(profile, 1), "tests") != 0 ||
        !tm_profile_allows_input_path(profile, "tests") ||
        tm_profile_allows_input_path(profile, "src-old/main.c") ||
        tm_profile_allows_input_path(profile, "../outside") ||
        tm_profile_allows_output_path(profile, "build/report")) {
        fprintf(stderr, "profile root permissions were not enforced\n");
        goto done;
    }
    memcpy(digest, tm_profile_digest(profile), sizeof(digest));
    tm_profile_free(profile);
    profile = NULL;
    if (tm_profile_load(path, &profile) < 0 ||
        strcmp(digest, tm_profile_digest(profile)) != 0) goto done;
    tm_profile_free(profile);
    profile = NULL;
    memcpy(valid_v2, valid, sizeof(valid));
    backend_name = strstr(valid_v2, "bubblewrap-linux-x86_64-v1");
    if (backend_name == NULL) goto done;
    backend_name[strlen("bubblewrap-linux-x86_64-v")] = '2';
    if (save(path, valid_v2) < 0 || tm_profile_load(path, &profile) < 0 ||
        strcmp(tm_profile_backend_contract(profile),
               "bubblewrap-linux-x86_64-v2") != 0 ||
        strcmp(tm_profile_digest(profile), digest) == 0) {
        fprintf(stderr, "profile did not preserve backend contract versioning\n");
        goto done;
    }
    tm_profile_free(profile);
    profile = NULL;
    if (save(path, nondeterministic) < 0 || tm_profile_load(path, &profile) < 0 ||
        tm_profile_is_deterministic(profile) != 0 ||
        strcmp(tm_profile_privacy_class(profile), "secret-dependent") != 0)
        goto done;
    tm_profile_free(profile);
    profile = NULL;
    if (save(path, unsafe) < 0 || tm_profile_load(path, &profile) == 0) {
        fprintf(stderr, "profile accepted a traversal input root\n");
        goto done;
    }
    if (save(path, overlap) < 0 || tm_profile_load(path, &profile) == 0) {
        fprintf(stderr, "profile accepted overlapping input/output roots\n");
        goto done;
    }
    if (save(path, metadata_input) < 0 || tm_profile_load(path, &profile) == 0) {
        fprintf(stderr, "profile exposed reserved metadata as an input root\n");
        goto done;
    }
    if (save(path, metadata_output) < 0 || tm_profile_load(path, &profile) == 0) {
        fprintf(stderr, "profile exposed reserved metadata as an output root\n");
        goto done;
    }
    if (save(path, metadata_scratch) < 0 || tm_profile_load(path, &profile) == 0) {
        fprintf(stderr, "profile overlapped scratch with reserved metadata\n");
        goto done;
    }
    if (save(path, output_profile) < 0 || tm_profile_load(path, &profile) < 0 ||
        !tm_profile_allows_output_path(profile, "build/report.json") ||
        tm_profile_allows_output_path(profile, "build-old/report.json")) {
        fprintf(stderr, "profile output root matching was incorrect\n");
        goto done;
    }
    status = 0;
done:
    tm_profile_free(profile);
    unlink(path);
    return status;
}
