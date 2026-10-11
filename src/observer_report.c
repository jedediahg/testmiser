#include "tm/observer.h"

int tm_observer_report_allows_reuse(const struct tm_observer_report *report)
{
    return report != 0 && report->observation_complete &&
           report->stable_input_view &&
           report->ineligibility_reasons == 0;
}

const char *tm_observer_ineligibility_description(unsigned int reason)
{
    switch (reason) {
    case TM_OBSERVER_INELIGIBLE_NETWORK:
        return "network or socket activity observed";
    case TM_OBSERVER_INELIGIBLE_MUTATION:
        return "filesystem mutation observed";
    case TM_OBSERVER_INELIGIBLE_METADATA:
        return "unmodeled filesystem metadata observed";
    case TM_OBSERVER_INELIGIBLE_DIRECTORY:
        return "directory enumeration uses native ordering";
    case TM_OBSERVER_INELIGIBLE_DESCRIPTOR:
        return "inherited or untracked descriptor observed";
    case TM_OBSERVER_INELIGIBLE_UNSUPPORTED:
        return "unsupported syscall or ABI observed";
    case TM_OBSERVER_INELIGIBLE_OBSERVER_FAILURE:
        return "observer lost coverage or failed";
    case TM_OBSERVER_INELIGIBLE_DESCENDANT:
        return "a child process outlived the direct command";
    case TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT:
        return "external filesystem input observed";
    case TM_OBSERVER_INELIGIBLE_UNSTABLE_VIEW:
        return "stable controlled filesystem view unavailable";
    case TM_OBSERVER_INELIGIBLE_UNMODELED_ERROR:
        return "unmodeled filesystem or descriptor error observed";
    case TM_OBSERVER_INELIGIBLE_CONTEXT:
        return "process or host context is outside the verified profile";
    default:
        return 0;
    }
}
