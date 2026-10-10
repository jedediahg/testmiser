#ifndef TM_RUNTIME_H
#define TM_RUNTIME_H

/* Digest a runtime tree by sorted relative paths, type, mode, link count,
 * file contents, and symlink target. Special files are rejected. */
int tm_runtime_tree_digest(const char *root, char output[72]);

/* Digest the directory currently referenced by an already-open descriptor. */
int tm_runtime_tree_digest_fd(int root_descriptor, char output[72]);

/* As above, but reject files/directories writable by the invoking user.
 * Writable roots covered by profile scratch tmpfs mounts are exempt. */
int tm_runtime_tree_digest_readonly_fd(int root_descriptor,
                                       const char *const *writable_roots,
                                       size_t writable_root_count,
                                       char output[72]);

#endif
