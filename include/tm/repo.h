#ifndef TM_REPO_H
#define TM_REPO_H

/* Resolve an explicit root, the nearest ancestor containing .git, or cwd. */
int tm_repo_root(const char *requested, char **output);

/* Return a repository-relative path, or NULL with errno=EXDEV if external. */
char *tm_repo_relative_path(const char *root, const char *absolute_path);

#endif
