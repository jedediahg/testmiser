#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "tm/observer.h"

int main(void)
{
#if defined(__linux__) && defined(__x86_64__)
    char *command[] = {"/bin/sh", "-c", "exec /bin/true", NULL};
    struct tm_observer_report report = {0};
    struct tm_observer_report controlled_report = {0};
    struct tm_observer_report identity_report = {0};
    struct tm_observer_report null_device_report = {0};
    struct tm_observer_report device_report = {0};
    struct tm_observer_report output_report = {0};
    struct tm_observer_report traversal_report = {0};
    struct tm_observer_report failed_report = {0};
    struct tm_observer_report mprotect_report = {0};
    struct tm_observer_report vdso_report = {0};
    struct tm_observer_report getcwd_report = {0};
    struct tm_observer_report metadata_report = {0};
    struct tm_observer_report descriptor_report = {0};
    struct tm_observer_report directory_report = {0};
    char repository[4096], device_executable[4200] = {0};
    char output_path[4200] = {0};
    char escape_path[4200] = {0};
    char failed_input_path[4200] = {0};
    char mprotect_input_path[4200] = {0};
    const char *output_roots[] = {"build/tm-observer-output-test"};
    char *output_command[] = {"./build/output_probe", NULL};
    char *null_device_command[] = {"./build/device_probe", "null", NULL};
    char *device_command[] = {"./build/device_probe", "random", NULL};
    char *traversal_command[] = {"/bin/sh", "-c",
        "printf escape > build/tm-observer-output-test/../tm-observer-output-escape", NULL};
    char *failed_command[] = {"./build/failing_read_probe",
        "build/tm-observer-failed-input", "23", NULL};
    char *mprotect_command[] = {"./build/mprotect_probe",
        "build/tm-observer-mprotect-input", NULL};
    char *private_mprotect_command[] = {"./build/mprotect_probe",
        "build/tm-observer-mprotect-input", "private", NULL};
    char *mixed_mprotect_command[] = {"./build/mprotect_probe",
        "build/tm-observer-mprotect-input", "mixed", NULL};
    char *vdso_command[] = {"./build/vdso_clock_probe", NULL, NULL};
    static const char *const vdso_clock_apis[] = {
        "clock_gettime", "clock_getres", "gettimeofday", "time"
    };
    char *getcwd_command[] = {"./build/getcwd_probe", NULL};
    char *metadata_command[] = {"./build/metadata_probe", "Makefile", NULL};
    char *descriptor_command[] = {"./build/descriptor_dup_probe", "Makefile", NULL};
    char *directory_command[] = {"./build/directory_probe", NULL, NULL};
    char *identity_command[] = {"./build/context_probe", "identity", NULL};
    size_t index, executable_count = 0;
    int result;
    if (syscall(SYS_close_range, 3U, ~0U, 0U) < 0) {
        perror("close inherited descriptors for observer test");
        return 1;
    }
    if (getcwd(repository, sizeof(repository)) == NULL) {
        fprintf(stderr, "could not determine observer test repository\n");
        return 1;
    }
    directory_command[1] = repository;
    if (snprintf(device_executable, sizeof(device_executable),
                 "%s/./build/device_probe", repository) >=
        (int)sizeof(device_executable)) {
        fprintf(stderr, "could not construct device probe path\n");
        return 1;
    }
    result = tm_observe_and_run_with_fds(command, 0, NULL, "/workspace",
        NULL, 0, 0, 0, "/bin/true", 0, NULL, 0, &report);
    if (report.candidate_count == 0 &&
        (report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE) != 0) {
        if (getenv("TM_REQUIRE_PTRACE") != NULL &&
            strcmp(getenv("TM_REQUIRE_PTRACE"), "1") == 0) {
            fprintf(stderr,
                "observer integration test requires ptrace, but tracing is unavailable\n");
            return 1;
        }
        puts("observer exec-boundary test skipped: ptrace unavailable");
        return 0;
    }
    for (index = 0; index < report.candidate_count; index++)
        if (strcmp(report.candidates[index].kind, "executable") == 0)
            executable_count++;
    if (result != 0 || executable_count != 1 ||
        report.observation_complete == 0 ||
        tm_observe_and_run_with_fds(command, 0, NULL, "/workspace", NULL,
            0, 0, 0, "/bin/true", 1, NULL, 0, &controlled_report) != 0 ||
        !controlled_report.stable_input_view ||
        (controlled_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT) != 0) {
        fprintf(stderr,
            "observer did not start at the requested executable (result=%d, candidates=%zu, reasons=0x%08x)\n",
            result, report.candidate_count, report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run_with_fds(null_device_command, 0, NULL,
            repository, NULL, 0, 1, 0, device_executable, 1, NULL, 0,
            &null_device_report) != 0 ||
        (null_device_report.ineligibility_reasons &
         (TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT |
          TM_OBSERVER_INELIGIBLE_DESCRIPTOR |
          TM_OBSERVER_INELIGIBLE_MUTATION)) != 0 ||
        !tm_observer_report_allows_reuse(&null_device_report)) {
        fprintf(stderr,
            "observer did not model controlled /dev/null access (reasons=0x%08x)\n",
            null_device_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run_with_fds_identity(identity_command, 0, NULL,
            repository, NULL, 0, 0, 0, NULL, 1, 1, NULL, 0,
            &identity_report) != 0 ||
        (identity_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_CONTEXT) == 0 ||
        tm_observer_report_allows_reuse(&identity_report)) {
        fprintf(stderr,
            "observer accepted nonzero identity results under normalized identity (reasons=0x%08x)\n",
            identity_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run_with_fds_identity(identity_command, 0, NULL,
            repository, NULL, 0, 0, 0, NULL, 1, 0, NULL, 0,
            &identity_report) != 0 ||
        (identity_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_CONTEXT) == 0 ||
        tm_observer_report_allows_reuse(&identity_report)) {
        fprintf(stderr,
            "observer accepted identity queries without v2 normalization (reasons=0x%08x)\n",
            identity_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run_with_fds_identity(identity_command, 0, NULL,
            repository, NULL, 0, 0, 0, NULL, 0, 1, NULL, 0,
            &identity_report) != 0 ||
        (identity_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_CONTEXT) == 0 ||
        tm_observer_report_allows_reuse(&identity_report)) {
        fprintf(stderr,
            "observer accepted identity normalization without a controlled runtime (reasons=0x%08x)\n",
            identity_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run_with_fds(device_command, 0, NULL, repository,
            NULL, 0, 0, 0, device_executable, 1, NULL, 0,
            &device_report) != 0 ||
        (device_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT) == 0 ||
        tm_observer_report_allows_reuse(&device_report)) {
        fprintf(stderr,
            "observer accepted /dev/urandom access in a controlled runtime (reasons=0x%08x)\n",
            device_report.ineligibility_reasons);
        return 1;
    }
    for (index = 0; index < sizeof(vdso_clock_apis) /
                            sizeof(vdso_clock_apis[0]); index++) {
        memset(&vdso_report, 0, sizeof(vdso_report));
        vdso_command[1] = (char *)vdso_clock_apis[index];
        result = tm_observe_and_run(vdso_command, 0, NULL, repository,
                                    &vdso_report);
        if (result != 0 ||
            (vdso_report.ineligibility_reasons &
             TM_OBSERVER_INELIGIBLE_UNSUPPORTED) == 0 ||
            tm_observer_report_allows_reuse(&vdso_report)) {
            fprintf(stderr,
                "observer did not reject vDSO clock API %s (result=%d, reasons=0x%08x)\n",
                vdso_clock_apis[index], result,
                vdso_report.ineligibility_reasons);
            return 1;
        }
    }
    if (getcwd(repository, sizeof(repository)) == NULL ||
        tm_observe_and_run(getcwd_command, 0, NULL, repository,
            &getcwd_report) != 0 ||
        (getcwd_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_METADATA) != 0) {
        fprintf(stderr,
            "observer treated getcwd as unmodeled filesystem metadata (reasons=0x%08x)\n",
            getcwd_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run(metadata_command, 0, NULL, repository,
            &metadata_report) != 0 ||
        (metadata_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_METADATA) == 0) {
        fprintf(stderr,
            "observer accepted unmodeled stat metadata (reasons=0x%08x)\n",
            metadata_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run(descriptor_command, 0, NULL, repository,
            &descriptor_report) != 0 ||
        (descriptor_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_DESCRIPTOR) != 0) {
        fprintf(stderr,
            "observer lost descriptor provenance across dup operations (reasons=0x%08x)\n",
            descriptor_report.ineligibility_reasons);
        return 1;
    }
    if (tm_observe_and_run(directory_command, 0, NULL, repository,
            &directory_report) != 0 ||
        (directory_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_DIRECTORY) == 0 ||
        tm_observer_report_allows_reuse(&directory_report)) {
        fprintf(stderr,
            "observer accepted directory enumeration with native ordering (reasons=0x%08x)\n",
            directory_report.ineligibility_reasons);
        return 1;
    }
    if (snprintf(output_path, sizeof(output_path), "%s/%s", repository,
                 output_roots[0]) >= (int)sizeof(output_path) ||
        snprintf(escape_path, sizeof(escape_path), "%s/build/tm-observer-output-escape",
                 repository) >= (int)sizeof(escape_path)) {
        fprintf(stderr, "could not construct output fixture paths\n");
        return 1;
    }
    result = tm_observe_and_run_with_fds(output_command, 0, NULL, repository,
        NULL, 0, 0, 0, NULL, 1, output_roots, 1, &output_report);
    if (result != 0 || (output_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_MUTATION) != 0) {
        fprintf(stderr,
            "observer did not classify declared output writes (result=%d, reasons=0x%08x)\n",
            result, output_report.ineligibility_reasons);
        if (output_path[0] != '\0') {
            char report_path[4300];
            if (snprintf(report_path, sizeof(report_path), "%s/sub/report",
                         output_path) < (int)sizeof(report_path))
                (void)unlink(report_path);
            if (snprintf(report_path, sizeof(report_path), "%s/sub",
                         output_path) < (int)sizeof(report_path))
                (void)rmdir(report_path);
            (void)rmdir(output_path);
        }
        return 1;
    }
    (void)unlink(escape_path);
    if (tm_observe_and_run_with_fds(traversal_command, 0, NULL, repository,
            NULL, 0, 0, 0, NULL, 1, output_roots, 1,
            &traversal_report) != 0 ||
        (traversal_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_MUTATION) == 0) {
        fprintf(stderr, "observer accepted traversal outside declared output\n");
        (void)unlink(escape_path);
        return 1;
    }
    (void)unlink(escape_path);
    {
        static const char input_contents[] = "failure-state-input\n";
        int descriptor;
        if (snprintf(failed_input_path, sizeof(failed_input_path),
                     "%s/build/tm-observer-failed-input", repository) >=
                (int)sizeof(failed_input_path) ||
            (descriptor = open(failed_input_path,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600)) < 0 ||
            write(descriptor, input_contents, sizeof(input_contents) - 1) !=
                (ssize_t)(sizeof(input_contents) - 1) || close(descriptor) < 0) {
            fprintf(stderr, "could not create failed-run input fixture\n");
            if (failed_input_path[0] != '\0') (void)unlink(failed_input_path);
            return 1;
        }
    }
    if (tm_observe_and_run_with_fds(failed_command, 0, NULL, repository,
            NULL, 0, 0, 0, NULL, 1, NULL, 0, &failed_report) != 23 ||
        !failed_report.observation_complete) {
        fprintf(stderr, "observer did not preserve a traced failed command\n");
        (void)unlink(failed_input_path);
        return 1;
    }
    {
        size_t candidate;
        int found_input = 0;
        for (candidate = 0; candidate < failed_report.candidate_count;
             candidate++)
            if (strcmp(failed_report.candidates[candidate].path,
                       "build/tm-observer-failed-input") == 0)
                found_input = 1;
        if (!found_input) {
            fprintf(stderr,
                    "failed command input was lost from the observer report\n");
            (void)unlink(failed_input_path);
            return 1;
        }
    }
    (void)unlink(failed_input_path);
    {
        int descriptor;
        if (snprintf(mprotect_input_path, sizeof(mprotect_input_path),
                     "%s/build/tm-observer-mprotect-input", repository) >=
                (int)sizeof(mprotect_input_path) ||
            (descriptor = open(mprotect_input_path,
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) < 0) {
            fprintf(stderr, "could not create mprotect observation fixture\n");
            if (mprotect_input_path[0] != '\0') (void)unlink(mprotect_input_path);
            return 1;
        }
        if (ftruncate(descriptor, 8192) < 0) {
            close(descriptor);
            fprintf(stderr, "could not size mprotect observation fixture\n");
            (void)unlink(mprotect_input_path);
            return 1;
        }
        if (close(descriptor) < 0) {
            fprintf(stderr, "could not close mprotect observation fixture\n");
            (void)unlink(mprotect_input_path);
            return 1;
        }
    }
    if (tm_observe_and_run_with_fds(mprotect_command, 0, NULL, repository,
            NULL, 0, 0, 0, NULL, 0, NULL, 0, &mprotect_report) != 0 ||
        (mprotect_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_MUTATION) == 0) {
        fprintf(stderr, "observer accepted writable mprotect on a shared mapping\n");
        (void)unlink(mprotect_input_path);
        return 1;
    }
    if (tm_observe_and_run_with_fds(private_mprotect_command, 0, NULL,
            repository, NULL, 0, 0, 0, NULL, 0, NULL, 0,
            &mprotect_report) != 0 ||
        (mprotect_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_MUTATION) != 0) {
        fprintf(stderr,
            "observer rejected a private copy-on-write mprotect mapping (reasons=0x%08x)\n",
            mprotect_report.ineligibility_reasons);
        (void)unlink(mprotect_input_path);
        return 1;
    }
    {
        unsigned char first_byte;
        int descriptor = open(mprotect_input_path, O_RDONLY | O_CLOEXEC);
        if (descriptor < 0 || read(descriptor, &first_byte, 1) != 1 ||
            close(descriptor) < 0 || first_byte != 0) {
            fprintf(stderr,
                "private mprotect changed its source file\n");
            if (descriptor >= 0) (void)close(descriptor);
            (void)unlink(mprotect_input_path);
            return 1;
        }
    }
    if (tm_observe_and_run_with_fds(mixed_mprotect_command, 0, NULL,
            repository, NULL, 0, 0, 0, NULL, 0, NULL, 0,
            &mprotect_report) != 0 ||
        (mprotect_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_MUTATION) == 0) {
        fprintf(stderr,
            "observer accepted mprotect across private and shared VMAs (reasons=0x%08x)\n",
            mprotect_report.ineligibility_reasons);
        (void)unlink(mprotect_input_path);
        return 1;
    }
    (void)unlink(mprotect_input_path);
    {
        char report_path[4300], directory_path[4300];
        if (snprintf(report_path, sizeof(report_path), "%s/sub/report",
                     output_path) < (int)sizeof(report_path))
            (void)unlink(report_path);
        if (snprintf(directory_path, sizeof(directory_path), "%s/sub",
                     output_path) < (int)sizeof(directory_path))
            (void)rmdir(directory_path);
        (void)rmdir(output_path);
    }
#endif
    return 0;
}
