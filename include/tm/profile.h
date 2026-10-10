#ifndef TM_PROFILE_H
#define TM_PROFILE_H

#include <stddef.h>

struct tm_profile;

int tm_profile_load(const char *path, struct tm_profile **output);
void tm_profile_free(struct tm_profile *profile);
const char *tm_profile_repository_id(const struct tm_profile *profile);
const char *tm_profile_digest(const struct tm_profile *profile);
const char *tm_profile_runtime_digest(const struct tm_profile *profile);
int tm_profile_is_deterministic(const struct tm_profile *profile);
const char *tm_profile_privacy_class(const struct tm_profile *profile);
size_t tm_profile_environment_count(const struct tm_profile *profile);
const char *tm_profile_environment_name(const struct tm_profile *profile,
                                        size_t index);
const char *tm_profile_environment_value(const struct tm_profile *profile,
                                         size_t index);

#endif
