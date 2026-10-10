#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/backend.h"
#include "tm/profile.h"

static int write_file(const char *path, const char *content)
{
    FILE *stream = fopen(path, "w");
    int result = 0;
    if (stream == NULL) return -1;
    if (fputs(content, stream) < 0) result = -1;
    if (fclose(stream) != 0) result = -1;
    return result;
}

int main(void)
{
    static const char profile_json[] =
        "{\"schema_version\":1,\"repository_id\":\"backend-test\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v2\","
        "\"runtime_digest\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"src\"],\"output_roots\":[],"
        "\"scratch_roots\":[\"/tmp\"]}";
    char temporary[] = "/tmp/tm-backend-test-XXXXXX";
    char profile_path[512] = {0}, log_path[512] = {0};
    char marker_path[512] = {0};
    char *repository_root = NULL;
    char *command[] = {"/bin/sh", "-c", "printf called >> \"$1\"", "sh",
                       marker_path, NULL};
    struct tm_profile *profile = NULL;
    int command_result = -1, status = 1, base_descriptor = -1;
    int high_descriptor = -1;
    mode_t original_umask = 0;
    int restore_umask = 0;
    char log_contents[64] = {0}, marker_contents[64] = {0};
    FILE *stream;

    if (mkdtemp(temporary) == NULL) return 1;
    if (snprintf(profile_path, sizeof(profile_path), "%s/profile.json",
                 temporary) >= (int)sizeof(profile_path) ||
        snprintf(log_path, sizeof(log_path), "%s/calls.log", temporary) >=
                 (int)sizeof(log_path) ||
        snprintf(marker_path, sizeof(marker_path), "%s/command.out",
                 temporary) >= (int)sizeof(marker_path)) goto done;
    repository_root = realpath(".", NULL);
    if (repository_root == NULL || write_file(profile_path, profile_json) < 0 ||
        setenv("TM_FAKE_BWRAP_LOG", log_path, 1) < 0 ||
        tm_profile_load(profile_path, &profile) < 0) goto done;
    {
        struct rlimit descriptor_limit;
        if (getrlimit(RLIMIT_NOFILE, &descriptor_limit) < 0) goto done;
        if (descriptor_limit.rlim_cur > 65536) {
            char descriptor_text[32];
            base_descriptor = open("/dev/null", O_RDONLY);
            if (base_descriptor < 0) goto done;
            high_descriptor = fcntl(base_descriptor, F_DUPFD, 65536);
            close(base_descriptor);
            base_descriptor = -1;
            if (high_descriptor < 65536 ||
                snprintf(descriptor_text, sizeof(descriptor_text), "%d",
                         high_descriptor) >= (int)sizeof(descriptor_text) ||
                setenv("TM_FAKE_BWRAP_FD", descriptor_text, 1) < 0)
                goto done;
        }
    }
    original_umask = umask(077);
    restore_umask = 1;

    if (tm_backend_run(profile, temporary, repository_root, NULL, 0, command,
                       0, NULL, &command_result) != 1 || command_result != 0) {
        stream = fopen(log_path, "r");
        if (stream != NULL) {
            char diagnostic[128];
            while (fgets(diagnostic, sizeof(diagnostic), stream) != NULL)
                fputs(diagnostic, stderr);
            fclose(stream);
        }
        goto done;
    }
    stream = fopen(log_path, "r");
    if (stream == NULL || fgets(log_contents, sizeof(log_contents), stream) ==
                          NULL || fgets(log_contents + 6,
                          sizeof(log_contents) - 6, stream) == NULL) {
        if (stream != NULL) fclose(stream);
        goto done;
    }
    fclose(stream);
    stream = fopen(marker_path, "r");
    if (stream == NULL || fgets(marker_contents, sizeof(marker_contents),
                                stream) == NULL) {
        if (stream != NULL) fclose(stream);
        goto done;
    }
    fclose(stream);
    if (strcmp(log_contents, "probe\ncommand\n") != 0 ||
        strcmp(marker_contents, "called") != 0) {
        fprintf(stderr, "backend probe or wrapped command ran incorrectly\n");
        goto done;
    }
    status = 0;
done:
    if (restore_umask) (void)umask(original_umask);
    if (base_descriptor >= 0) close(base_descriptor);
    if (high_descriptor >= 0) close(high_descriptor);
    tm_profile_free(profile);
    free(repository_root);
    if (profile_path[0] != '\0') unlink(profile_path);
    if (log_path[0] != '\0') unlink(log_path);
    if (marker_path[0] != '\0') unlink(marker_path);
    rmdir(temporary);
    if (status != 0) fprintf(stderr, "backend test failed: %s\n",
                             strerror(errno));
    return status;
}
