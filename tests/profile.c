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
    struct tm_profile *profile = NULL;
    char path[] = "/tmp/tm-profile-test-XXXXXX";
    char digest[72];
    int fd = mkstemp(path), status = 1;
    if (fd < 0) return 1;
    close(fd);
    if (save(path, valid) < 0 || tm_profile_load(path, &profile) < 0 ||
        strcmp(tm_profile_repository_id(profile), "sample") != 0 ||
        strlen(tm_profile_digest(profile)) != 71 ||
        strcmp(tm_profile_digest(profile),
          "sha256:9594caa6d198b87e03b0dbfd5a869f6096ad69f889dd06bf10b8094cabb716dc") != 0)
        goto done;
    memcpy(digest, tm_profile_digest(profile), sizeof(digest));
    tm_profile_free(profile);
    profile = NULL;
    if (tm_profile_load(path, &profile) < 0 ||
        strcmp(digest, tm_profile_digest(profile)) != 0) goto done;
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
    status = 0;
done:
    tm_profile_free(profile);
    unlink(path);
    return status;
}
