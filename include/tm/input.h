#ifndef TM_INPUT_H
#define TM_INPUT_H

#include "tm/verification.h"

/* Capture a stable regular file below root_fd as a sha256-prefixed digest.
 * Symlink traversal and unsupported paths fail closed. */
int tm_input_capture_file(int root_fd, const char *path, char digest[72]);

/* Compare one recorded input with the current repository view rooted at an
 * already-open directory. Return 0 for a match, 1 for changed state, -1 for
 * unsafe, unsupported, or failed inspection. Symlink traversal is rejected;
 * callers must record each link and validate against a stable view. File
 * metadata is only equivalent under a backend that canonicalizes the view. */
int tm_input_matches(int root_fd,
                     const struct tm_input_observation *observation);

#endif
