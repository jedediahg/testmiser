#ifndef TM_OUTPUTS_H
#define TM_OUTPUTS_H

#include <stddef.h>
#include <stdint.h>

enum tm_output_kind { TM_OUTPUT_FILE, TM_OUTPUT_DIRECTORY };

struct tm_output_entry {
    char *path;
    enum tm_output_kind kind;
    uint32_t mode;
    char digest[72];
    uint64_t size;
};

struct tm_output_manifest {
    struct tm_output_entry *entries;
    size_t count;
};

/* Validate canonical, non-overlapping repository-relative output roots. */
int tm_output_roots_validate(const char *const *roots, size_t root_count);

/* Initialize manifest to {0}; capture is stable only when the caller supplies
 * an isolated output view. Blobs are durably published under
 * .tm/blobs/sha256/<hex-digest>. Published orphan blobs are harmless. */
int tm_outputs_capture(int repository_root_fd, const char *const *roots,
                       size_t root_count, struct tm_output_manifest *manifest);
/* Verify all referenced blobs, stage each declared root beside its target,
 * then replace that root. Only the supplied roots may be modified. */
int tm_outputs_restore(int repository_root_fd, const char *const *roots,
                       size_t root_count,
                       const struct tm_output_manifest *manifest);
void tm_output_manifest_clear(struct tm_output_manifest *manifest);

#endif
