#ifndef TM_LOCAL_STORE_H
#define TM_LOCAL_STORE_H

/* Open an absolute directory path without following symlinks or dot segments. */
int tm_open_directory_without_symlinks(const char *path);

/* Return an allocated, validated XDG_CACHE_HOME or $HOME/.cache path. */
int tm_user_cache_root(char **cache_root);

/* Open/create a repository-independent result-store root below a caller-owned
 * cache directory. The returned descriptor is owned by the caller. */
int tm_local_store_open(const char *cache_root, int *store_root_fd);

/* Resolve XDG_CACHE_HOME or $HOME/.cache and open its TestMiser store. */
int tm_local_store_open_default(int *store_root_fd);

/* Open the optional shared filesystem store configured by TM_SHARED_STORE.
 * Returns 0 when opened, 1 when unset, and -1 when configured but unusable. */
int tm_shared_store_open_configured(int *store_root_fd);

#endif
