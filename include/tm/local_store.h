#ifndef TM_LOCAL_STORE_H
#define TM_LOCAL_STORE_H

/* Open/create a repository-independent result-store root below a caller-owned
 * cache directory. The returned descriptor is owned by the caller. */
int tm_local_store_open(const char *cache_root, int *store_root_fd);

#endif
