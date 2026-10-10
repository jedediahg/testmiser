#include <assert.h>

#include "tm/observer.h"

int main(void)
{
    struct tm_observer_report report = {0};

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

    report.ineligibility_reasons = 0;
    report.observation_complete = 0;
    assert(!tm_observer_report_allows_reuse(&report));
    return 0;
}
