#ifndef TM_PROFILE_H
#define TM_PROFILE_H

struct tm_profile;

int tm_profile_load(const char *path, struct tm_profile **output);
void tm_profile_free(struct tm_profile *profile);
const char *tm_profile_repository_id(const struct tm_profile *profile);
const char *tm_profile_digest(const struct tm_profile *profile);

#endif
