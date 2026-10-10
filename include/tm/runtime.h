#ifndef TM_RUNTIME_H
#define TM_RUNTIME_H

/* Digest a runtime tree by sorted relative paths, type, mode, link count,
 * file contents, and symlink target. Special files are rejected. */
int tm_runtime_tree_digest(const char *root, char output[72]);

#endif
