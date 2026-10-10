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
#include "tm/digest.h"
#include "tm/observer.h"
#include "tm/profile.h"
#include "tm/runtime.h"
#include "tm/snapshot.h"

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
    static const char profile_template[] =
        "{\"schema_version\":1,\"repository_id\":\"backend-test\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v2\","
        "\"runtime_digest\":\"%s\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"build/tm-backend-input\"],\"output_roots\":[],"
        "\"scratch_roots\":[\"/tmp\"]}";
    static const char symlink_profile_template[] =
        "{\"schema_version\":1,\"repository_id\":\"backend-test\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v2\","
        "\"runtime_digest\":\"%s\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"build/.tm-backend-root-link\"],"
        "\"output_roots\":[],\"scratch_roots\":[\"/tmp\"]}";
    static const char output_profile_template[] =
        "{\"schema_version\":1,\"repository_id\":\"backend-test\","
        "\"backend_contract\":\"bubblewrap-linux-x86_64-v2\","
        "\"runtime_digest\":\"%s\","
        "\"workspace_path\":\"/workspace\",\"deterministic\":true,"
        "\"privacy_class\":\"public\",\"environment\":{},"
        "\"input_roots\":[\"build/tm-backend-input\"],"
        "\"output_roots\":[\"build/tm-backend-output\"],"
        "\"scratch_roots\":[\"/tmp\"]}";
    char temporary[] = "/tmp/tm-backend-test-XXXXXX";
    char profile_path[512] = {0}, log_path[512] = {0};
    char runtime_path[512] = {0}, runtime_digest[72] = {0};
    char profile_json[1024], symlink_profile_json[1024];
    char output_profile_json[1024];
    char marker_path[512] = {0};
    char output_path[512] = {0}, output_file[512] = {0};
    char blob_path[512] = {0};
    char input_link_path[512] = {0};
    char input_root_path[512] = {0}, input_file_path[512] = {0};
    char nested_root_path[512] = {0}, nested_file_path[512] = {0};
    char readonly_root_path[512] = {0}, readonly_file_path[512] = {0};
    char input_symlink_path[512] = {0};
    char *repository_root = NULL;
    char *command[] = {"/bin/sh", "-c", "printf called >> \"$1\"", "sh",
                       marker_path, NULL};
    char *output_command[] = {"/bin/true", NULL};
    const char *output_roots[] = {"build/tm-backend-output"};
    struct tm_profile *profile = NULL;
    struct tm_observer_report observer_report = {0};
    struct tm_observed_input_manifest observed_inputs = {0};
    struct tm_output_manifest outputs = {0};
    char *resolved_bwrap = NULL;
    char bwrap_digest[72];
    int command_result = -1, status = 1, base_descriptor = -1;
    int high_descriptor = -1;
    int blob_existed = 0;
    int preflight_repository_fd = -1;
    struct tm_snapshot *preflight_snapshot = NULL;
    mode_t original_umask = 0;
    int restore_umask = 0;
    char log_contents[64] = {0}, marker_contents[64] = {0};
    FILE *stream;

    if (tm_backend_executable_identity(&resolved_bwrap, bwrap_digest) < 0 ||
        strncmp(bwrap_digest, "sha256:", 7) != 0 ||
        strlen(bwrap_digest) != 71 || resolved_bwrap == NULL) {
        free(resolved_bwrap);
        return 1;
    }
    free(resolved_bwrap);
    if (mkdtemp(temporary) == NULL) return 1;
    if (snprintf(profile_path, sizeof(profile_path), "%s/profile.json",
                 temporary) >= (int)sizeof(profile_path) ||
        snprintf(log_path, sizeof(log_path), "%s/calls.log", temporary) >=
                 (int)sizeof(log_path) ||
        snprintf(marker_path, sizeof(marker_path), "%s/command.out",
                 temporary) >= (int)sizeof(marker_path) ||
        snprintf(runtime_path, sizeof(runtime_path), "%s/runtime", temporary) >=
                 (int)sizeof(runtime_path) || mkdir(runtime_path, 0755) < 0 ||
        tm_runtime_tree_digest(runtime_path, runtime_digest) < 0 ||
        snprintf(profile_json, sizeof(profile_json), profile_template,
                 runtime_digest) >= (int)sizeof(profile_json) ||
        snprintf(symlink_profile_json, sizeof(symlink_profile_json),
                 symlink_profile_template, runtime_digest) >=
                 (int)sizeof(symlink_profile_json) ||
        snprintf(output_profile_json, sizeof(output_profile_json),
                 output_profile_template, runtime_digest) >=
                 (int)sizeof(output_profile_json))
        goto done;
    repository_root = realpath(".", NULL);
    if (repository_root == NULL ||
        snprintf(output_path, sizeof(output_path),
                 "%s/build/tm-backend-output", repository_root) >=
                 (int)sizeof(output_path) ||
        snprintf(output_file, sizeof(output_file), "%s/report.txt",
                 output_path) >= (int)sizeof(output_file) ||
        snprintf(blob_path, sizeof(blob_path),
                 "%s/.tm/blobs/sha256/", repository_root) >=
                 (int)sizeof(blob_path) ||
        snprintf(input_link_path, sizeof(input_link_path),
                 "%s/build/.tm-backend-root-link", repository_root) < 0 ||
        snprintf(input_root_path, sizeof(input_root_path),
                 "%s/build/tm-backend-input", repository_root) < 0 ||
        snprintf(input_file_path, sizeof(input_file_path),
                 "%s/build/tm-backend-input/input.txt", repository_root) < 0 ||
        snprintf(nested_root_path, sizeof(nested_root_path),
                 "%s/build/tm-backend-input/nested", repository_root) < 0 ||
        snprintf(nested_file_path, sizeof(nested_file_path),
                 "%s/build/tm-backend-input/nested/nested.txt",
                 repository_root) < 0 ||
        snprintf(readonly_root_path, sizeof(readonly_root_path),
                 "%s/build/tm-backend-input/readonly", repository_root) < 0 ||
        snprintf(readonly_file_path, sizeof(readonly_file_path),
                 "%s/build/tm-backend-input/readonly/locked.txt",
                 repository_root) < 0 ||
        snprintf(input_symlink_path, sizeof(input_symlink_path),
                 "%s/build/tm-backend-input/link", repository_root) < 0 ||
        strlen(repository_root) + sizeof("/build/.tm-backend-root-link") >
            sizeof(input_link_path) ||
        mkdir(input_root_path, 0700) < 0 ||
        mkdir(nested_root_path, 0700) < 0 ||
        mkdir(readonly_root_path, 0700) < 0 ||
        write_file(input_file_path, "original") < 0 ||
        write_file(nested_file_path, "nested") < 0 ||
        write_file(readonly_file_path, "locked") < 0 ||
        chmod(readonly_root_path, 0500) < 0 ||
        symlink("input.txt", input_symlink_path) < 0 ||
        setenv("TM_FAKE_BWRAP_INPUT_FILE", input_file_path, 1) < 0 ||
        write_file(profile_path, profile_json) < 0 ||
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

    {
        const char *preflight_roots[] = {"build/tm-backend-input"};
        preflight_repository_fd = open(repository_root,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (preflight_repository_fd < 0 ||
            tm_snapshot_create(preflight_repository_fd, preflight_roots, 1,
                               &preflight_snapshot) < 0 ||
            unsetenv("TM_FAKE_BWRAP_INPUT_FILE") < 0 ||
            tm_backend_preflight(profile, runtime_path, repository_root,
                                 preflight_snapshot) != 1 ||
            unlink(log_path) < 0 ||
            setenv("TM_FAKE_BWRAP_INPUT_FILE", input_file_path, 1) < 0) {
            fprintf(stderr, "backend cache preflight did not pass its probe\n");
            goto done;
        }
        tm_snapshot_free(preflight_snapshot);
        preflight_snapshot = NULL;
        close(preflight_repository_fd);
        preflight_repository_fd = -1;
    }

    if (tm_backend_run(profile, runtime_path, repository_root, NULL, 0, command,
                       0, &observer_report, &observed_inputs,
                       &outputs,
                       &command_result) != 1 ||
        command_result != 0) {
        stream = fopen(log_path, "r");
        if (stream != NULL) {
            char diagnostic[128];
            while (fgets(diagnostic, sizeof(diagnostic), stream) != NULL)
                fputs(diagnostic, stderr);
            fclose(stream);
        }
        goto done;
    }
    if (observer_report.stable_input_view ||
        (observer_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW) == 0) {
        fprintf(stderr, "profile observer incorrectly claimed a stable report\n");
        goto done;
    }
    stream = fopen(input_file_path, "r");
    if (stream == NULL || fgets(marker_contents, sizeof(marker_contents),
                                stream) == NULL ||
        strcmp(marker_contents, "changed") != 0) {
        if (stream != NULL) fclose(stream);
        fprintf(stderr, "fake Bubblewrap did not mutate the source input\n");
        goto done;
    }
    fclose(stream);
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
    if (symlink("tm-backend-input", input_link_path) < 0 ||
        write_file(profile_path, symlink_profile_json) < 0) goto done;
    tm_profile_free(profile);
    profile = NULL;
    if (tm_profile_load(profile_path, &profile) < 0) goto done;
    command_result = -1;
    if (tm_backend_run(profile, runtime_path, repository_root, NULL, 0, command,
                       0, NULL, NULL, NULL, &command_result) != 0 ||
        command_result != -1) {
        fprintf(stderr, "backend accepted a symlinked profile input root\n");
        goto done;
    }
    stream = fopen(log_path, "r");
    if (stream == NULL || fgets(log_contents, sizeof(log_contents), stream) ==
                          NULL || fgets(log_contents + 6,
                          sizeof(log_contents) - 6, stream) == NULL ||
        fgets(marker_contents, sizeof(marker_contents), stream) != NULL) {
        if (stream != NULL) fclose(stream);
        fprintf(stderr, "backend launched Bubblewrap for an unsafe input root\n");
        goto done;
    }
    fclose(stream);
    {
        static const unsigned char expected_output[] = "captured report\n";
        char digest[65];
        size_t blob_directory_length;
        if (unlink(input_link_path) < 0 ||
            write_file(input_file_path, "original") < 0 ||
            write_file(profile_path, output_profile_json) < 0 ||
            tm_sha256_bytes(expected_output, sizeof(expected_output) - 1,
                            digest) < 0) goto done;
        tm_profile_free(profile);
        profile = NULL;
        if (tm_profile_load(profile_path, &profile) < 0) goto done;
        blob_directory_length = strlen(blob_path);
        if (snprintf(blob_path + blob_directory_length,
                     sizeof(blob_path) - blob_directory_length, "%s", digest) >=
            (int)(sizeof(blob_path) - blob_directory_length)) goto done;
        blob_existed = access(blob_path, F_OK) == 0;
        blob_path[blob_directory_length] = '\0';
        (void)unlink(output_file);
        (void)rmdir(output_path);
        command_result = -1;
        if (tm_backend_run(profile, runtime_path, repository_root, output_roots,
                1, output_command, 0, &observer_report, &observed_inputs,
                &outputs, &command_result) != 1 || command_result != 0 ||
            outputs.count != 2 || access(output_file, F_OK) < 0) {
            fprintf(stderr,
                    "backend did not capture and restore its staged output\n");
            goto done;
        }
        stream = fopen(output_file, "r");
        if (stream == NULL || fgets(marker_contents, sizeof(marker_contents),
                                    stream) == NULL ||
            strcmp(marker_contents, "captured report\n") != 0) {
            if (stream != NULL) fclose(stream);
            goto done;
        }
        fclose(stream);
        stream = NULL;
    }
    status = 0;
done:
    tm_output_manifest_clear(&outputs);
    tm_observed_input_manifest_clear(&observed_inputs);
    if (restore_umask) (void)umask(original_umask);
    tm_snapshot_free(preflight_snapshot);
    if (preflight_repository_fd >= 0) close(preflight_repository_fd);
    if (base_descriptor >= 0) close(base_descriptor);
    if (high_descriptor >= 0) close(high_descriptor);
    tm_profile_free(profile);
    free(repository_root);
    if (profile_path[0] != '\0') unlink(profile_path);
    if (log_path[0] != '\0') unlink(log_path);
    if (marker_path[0] != '\0') unlink(marker_path);
    if (output_file[0] != '\0') unlink(output_file);
    if (output_path[0] != '\0') rmdir(output_path);
    if (!blob_existed && blob_path[0] != '\0') {
        char full_blob_path[512];
        if (snprintf(full_blob_path, sizeof(full_blob_path), "%s", blob_path) <
            (int)sizeof(full_blob_path)) {
            static const unsigned char expected_output[] = "captured report\n";
            char digest[65];
            if (tm_sha256_bytes(expected_output, sizeof(expected_output) - 1,
                                digest) == 0 &&
                snprintf(full_blob_path + strlen(blob_path),
                         sizeof(full_blob_path) - strlen(blob_path), "%s",
                         digest) <
                    (int)(sizeof(full_blob_path) - strlen(blob_path)))
                (void)unlink(full_blob_path);
        }
    }
    if (input_link_path[0] != '\0') unlink(input_link_path);
    if (input_file_path[0] != '\0') unlink(input_file_path);
    if (nested_file_path[0] != '\0') unlink(nested_file_path);
    if (input_symlink_path[0] != '\0') unlink(input_symlink_path);
    if (readonly_root_path[0] != '\0') {
        (void)chmod(readonly_root_path, 0700);
        if (readonly_file_path[0] != '\0') unlink(readonly_file_path);
        rmdir(readonly_root_path);
    }
    if (nested_root_path[0] != '\0') rmdir(nested_root_path);
    if (input_root_path[0] != '\0') rmdir(input_root_path);
    if (runtime_path[0] != '\0') rmdir(runtime_path);
    rmdir(temporary);
    if (status != 0) fprintf(stderr, "backend test failed: %s\n",
                             strerror(errno));
    return status;
}
