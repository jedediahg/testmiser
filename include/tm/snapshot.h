#ifndef TM_SNAPSHOT_H
#define TM_SNAPSHOT_H

#include <stddef.h>

struct tm_snapshot;

/* Copy approved repository roots into a private staging tree. Source trees
 * must retain identical per-node metadata/content before and after copying;
 * unsupported ownership, links, or a copy above 4 GiB are rejected. */
int tm_snapshot_create(int repository_fd, const char *const *paths,
                       size_t path_count, struct tm_snapshot **snapshot);
int tm_snapshot_open_root(const struct tm_snapshot *snapshot, size_t index);
/* Open a snapshot root for content capture (unlike the O_PATH bind handle). */
int tm_snapshot_open_root_readable(const struct tm_snapshot *snapshot,
                                   size_t index);
void tm_snapshot_free(struct tm_snapshot *snapshot);

#endif
