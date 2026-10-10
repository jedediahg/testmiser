#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tm/observer.h"

int main(void)
{
#if defined(__linux__) && defined(__x86_64__)
    char *command[] = {"/bin/sh", "-c", "exec /bin/true", NULL};
    struct tm_observer_report report = {0};
    struct tm_observer_report controlled_report = {0};
    struct tm_observer_report output_report = {0};
    struct tm_observer_report traversal_report = {0};
    char repository[4096], output_path[4200] = {0};
    char escape_path[4200] = {0};
    const char *output_roots[] = {"build/tm-observer-output-test"};
    char *output_command[] = {"/bin/sh", "-c",
        "mkdir build/tm-observer-output-test/sub && printf data > build/tm-observer-output-test/sub/report", NULL};
    char *traversal_command[] = {"/bin/sh", "-c",
        "printf escape > build/tm-observer-output-test/../tm-observer-output-escape", NULL};
    size_t index, executable_count = 0;
    int result = tm_observe_and_run_with_fds(command, 0, NULL, "/workspace",
        NULL, 0, 0, 0, "/bin/true", 0, NULL, 0, &report);
    if (report.candidate_count == 0 &&
        (report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE) != 0) {
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
    if (getcwd(repository, sizeof(repository)) == NULL ||
        snprintf(output_path, sizeof(output_path), "%s/%s", repository,
                 output_roots[0]) >= (int)sizeof(output_path) ||
        snprintf(escape_path, sizeof(escape_path), "%s/build/tm-observer-output-escape",
                 repository) >= (int)sizeof(escape_path) ||
        tm_observe_and_run_with_fds(output_command, 0, NULL, repository,
            NULL, 0, 0, 0, NULL, 1, output_roots, 1, &output_report) != 0 ||
        (output_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_MUTATION) != 0) {
        fprintf(stderr, "observer did not classify declared output writes\n");
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
