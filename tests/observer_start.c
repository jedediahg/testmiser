#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>

#include "tm/observer.h"

int main(void)
{
#if defined(__linux__) && defined(__x86_64__)
    char *command[] = {"/bin/sh", "-c", "exec /bin/true", NULL};
    struct tm_observer_report report = {0};
    struct tm_observer_report controlled_report = {0};
    size_t index, executable_count = 0;
    int result = tm_observe_and_run_with_fds(command, 0, NULL, "/workspace",
        NULL, 0, 0, 0, "/bin/true", 0, &report);
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
            0, 0, 0, "/bin/true", 1, &controlled_report) != 0 ||
        (controlled_report.ineligibility_reasons &
         TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT) != 0) {
        fprintf(stderr,
            "observer did not start at the requested executable (result=%d, candidates=%zu, reasons=0x%08x)\n",
            result, report.candidate_count, report.ineligibility_reasons);
        return 1;
    }
#endif
    return 0;
}
