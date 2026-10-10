#ifndef TM_INPUT_H
#define TM_INPUT_H

#include "tm/verification.h"

/* Capture a stable regular file below root_fd as a sha256-prefixed digest.
 * Symlink traversal and unsupported paths fail closed. */
int tm_input_capture_file(int root_fd, const char *path, char digest[72]);
/* Capture bytes from an already-open regular file root. */
int tm_input_capture_file_root(int file_fd, char digest[72]);

/* Capture a stable directory-membership digest. File contents require their
 * own file observations; the directory digest records names and entry kinds. */
int tm_input_capture_directory(int root_fd, const char *path, char digest[72]);
/* Capture membership for the directory represented by root_fd itself. */
int tm_input_capture_directory_root(int root_fd, char digest[72]);

/* Capture whether a canonical path is absent without following symlinks. */
int tm_input_capture_exists(int root_fd, const char *path, int *exists);

/* Capture a stable relative symlink target. The caller owns *target. Absolute
 * targets, invalid UTF-8, and targets containing `..` are rejected. */
int tm_input_capture_symlink(int root_fd, const char *path, char **target);

/* Compare one recorded input with the current repository view rooted at an
 * already-open directory. Return 0 for a match, 1 for changed state, -1 for
 * unsafe, unsupported, or failed inspection. Symlink traversal is rejected;
 * callers must record each link and validate against a stable view. File
 * metadata is only equivalent under a backend that canonicalizes the view. */
int tm_input_matches(int root_fd,
                     const struct tm_input_observation *observation);

#endif
