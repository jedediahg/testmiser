#include "tm/observer.h"

int tm_observer_report_allows_reuse(const struct tm_observer_report *report)
{
    return report != 0 && report->observation_complete &&
           report->ineligibility_reasons == 0;
}
