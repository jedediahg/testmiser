#include <assert.h>
#include <string.h>

#include "tm/observer.h"

int main(void)
{
    static const struct {
        unsigned int reason;
        const char *description;
    } descriptions[] = {
        {TM_OBSERVER_INELIGIBLE_NETWORK,
         "network or socket activity observed"},
        {TM_OBSERVER_INELIGIBLE_MUTATION, "filesystem mutation observed"},
        {TM_OBSERVER_INELIGIBLE_METADATA,
         "unmodeled filesystem metadata observed"},
        {TM_OBSERVER_INELIGIBLE_DIRECTORY,
         "directory enumeration uses native ordering"},
        {TM_OBSERVER_INELIGIBLE_DESCRIPTOR,
         "inherited or untracked descriptor observed"},
        {TM_OBSERVER_INELIGIBLE_UNSUPPORTED,
         "unsupported syscall or ABI observed"},
        {TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE,
         "observer lost coverage or failed"},
        {TM_OBSERVER_INELIGIBLE_DESCENDANT,
         "a child process outlived the direct command"},
        {TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT,
         "external filesystem input observed"},
        {TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW,
         "stable controlled filesystem view unavailable"},
        {TM_OBSERVER_INELIGIBLE_UNMODELED_ERROR,
         "unmodeled filesystem or descriptor error observed"},
        {TM_OBSERVER_INELIGIBLE_CONTEXT,
         "process or host context is outside the verified profile"}
    };
    struct tm_observer_report report = {0};
    size_t index;

    for (index = 0; index < sizeof(descriptions) / sizeof(descriptions[0]);
         index++)
        assert(tm_observer_ineligibility_description(
                   descriptions[index].reason) != NULL &&
               strcmp(tm_observer_ineligibility_description(
                          descriptions[index].reason),
                      descriptions[index].description) == 0);
    assert(tm_observer_ineligibility_description(0) == NULL);
    assert(tm_observer_ineligibility_description(1U << 31) == NULL);

    assert(!tm_observer_report_allows_reuse(NULL));
    assert(!tm_observer_report_allows_reuse(&report));

    report.observation_complete = 1;
    assert(!tm_observer_report_allows_reuse(&report));
    report.stable_input_view = 1;
    assert(tm_observer_report_allows_reuse(&report));

    report.ineligibility_reasons = TM_OBSERVER_INELIGIBLE_NETWORK;
    assert(!tm_observer_report_allows_reuse(&report));
    report.ineligibility_reasons = TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE;
    assert(!tm_observer_report_allows_reuse(&report));
    report.ineligibility_reasons = TM_OBSERVER_INELIGIBLE_UNMODELED_ERROR;
    assert(!tm_observer_report_allows_reuse(&report));
    report.ineligibility_reasons = TM_OBSERVER_INELIGIBLE_CONTEXT;
    assert(!tm_observer_report_allows_reuse(&report));

    report.ineligibility_reasons = 0;
    report.observation_complete = 0;
    assert(!tm_observer_report_allows_reuse(&report));
    return 0;
}
