#ifndef TM_CONTEXT_H
#define TM_CONTEXT_H

#include "tm/json.h"

/* Hash canonical delivered-environment and execution-context objects using
 * the tm-context-v2 domain. */
int tm_context_fingerprint(const struct tm_json_value *environment,
                           const struct tm_json_value *execution_context,
                           char output[72]);

#endif
