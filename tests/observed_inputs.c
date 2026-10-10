#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/observed_inputs.h"

static int write_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t length = strlen(text), offset = 0;
    if (fd < 0) return -1;
    while (offset < length) {
        ssize_t count = write(fd, text + offset, length - offset);
        if (count < 0) { close(fd); return -1; }
        offset += (size_t)count;
    }
    return close(fd);
}

int main(void)
{
    char directory[] = "/tmp/tm-observed-inputs-XXXXXX";
    char file[512], link_path[512];
    struct tm_observer_report report = {0};
    struct tm_observed_input_manifest manifest = {0};
    int root = -1, status = 1;

    if (mkdtemp(directory) == NULL) return 1;
    if (snprintf(file, sizeof(file), "%s/alpha", directory) >=
            (int)sizeof(file) ||
        snprintf(link_path, sizeof(link_path), "%s/link", directory) >=
            (int)sizeof(link_path) ||
        write_file(file, "observed\n") < 0 ||
        symlink("alpha", link_path) < 0) goto done;
    root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) goto done;

    report.observation_complete = 1;
    report.stable_input_view = 1;
    report.candidate_count = 4;
    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "opened file");
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path), "alpha");
    snprintf(report.candidates[1].kind,
             sizeof(report.candidates[1].kind), "read descriptor");
    snprintf(report.candidates[1].path,
             sizeof(report.candidates[1].path), "alpha");
    snprintf(report.candidates[2].kind,
             sizeof(report.candidates[2].kind), "absent path");
    snprintf(report.candidates[2].path,
             sizeof(report.candidates[2].path), "not-created");
    snprintf(report.candidates[3].kind,
             sizeof(report.candidates[3].kind), "symlink");
    snprintf(report.candidates[3].path,
             sizeof(report.candidates[3].path), "link");

    if (tm_observer_capture_inputs(&report, root, &manifest) < 0 ||
        manifest.count != 3 ||
        strcmp(manifest.items[0].path, "alpha") != 0 ||
        manifest.items[0].kind != TM_INPUT_FILE ||
        strncmp(manifest.items[0].digest, "sha256:", 7) != 0 ||
        strcmp(manifest.items[1].path, "link") != 0 ||
        manifest.items[1].kind != TM_INPUT_SYMLINK ||
        strcmp(manifest.items[1].target, "alpha") != 0 ||
        strcmp(manifest.items[2].path, "not-created") != 0 ||
        manifest.items[2].kind != TM_INPUT_EXISTS ||
        manifest.items[2].exists != 0) {
        fprintf(stderr, "observed candidates were not captured canonically\n");
        goto done;
    }
    tm_observed_input_manifest_clear(&manifest);

    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "metadata probe");
    if (tm_observer_capture_inputs(&report, root, &manifest) == 0) {
        fprintf(stderr, "unsupported observation was accepted\n");
        goto done;
    }
    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "opened file");
    report.ineligibility_reasons = TM_OBSERVER_INELIGIBLE_EXTERNAL_INPUT;
    if (tm_observer_capture_inputs(&report, root, &manifest) == 0) {
        fprintf(stderr, "ineligible report was captured\n");
        goto done;
    }
    status = 0;
done:
    tm_observed_input_manifest_clear(&manifest);
    if (root >= 0) close(root);
    unlink(link_path);
    unlink(file);
    rmdir(directory);
    return status;
}
