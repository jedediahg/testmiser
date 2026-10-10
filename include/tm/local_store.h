#ifndef TM_LOCAL_STORE_H
#define TM_LOCAL_STORE_H

/* Return an allocated, validated XDG_CACHE_HOME or $HOME/.cache path. */
int tm_user_cache_root(char **cache_root);

/* Open/create a repository-independent result-store root below a caller-owned
 * cache directory. The returned descriptor is owned by the caller. */
int tm_local_store_open(const char *cache_root, int *store_root_fd);

/* Resolve XDG_CACHE_HOME or $HOME/.cache and open its TestMiser store. */
int tm_local_store_open_default(int *store_root_fd);

#endif
