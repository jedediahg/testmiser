#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tm/input.h"
#include "tm/observed_inputs.h"
#include "tm/snapshot.h"

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
    char file[512] = {0}, link_path[512] = {0};
    char subdirectory[512] = {0}, child[512] = {0}, extra[512] = {0};
    char symlink_root[512] = {0}, symlink_target[512] = {0};
    char symlink_other[512] = {0}, symlink_one[512] = {0};
    char symlink_two[512] = {0}, symlink_directory[512] = {0};
    char symlink_child[512] = {0}, symlink_dir_link[512] = {0};
    char symlink_escape[512] = {0}, symlink_absolute[512] = {0};
    char symlink_chain[TM_OBSERVED_INPUT_MAX_SYMLINKS + 1][512] = {{0}};
    struct tm_observer_report report = {0};
    struct tm_observed_input_manifest manifest = {0};
    struct tm_snapshot *snapshot = NULL, *changed_snapshot = NULL;
    const char *snapshot_paths[] = {"subdir"};
    const char *file_snapshot_paths[] = {"alpha"};
    const char *symlink_snapshot_paths[] = {"symlink-root"};
    int snapshot_root = -1, snapshot_roots[1], symlink_snapshot_root = -1;
    int changed_snapshot_root = -1;
    char snapshot_digest[72];
    int root = -1, status = 1;
    size_t chain_index;

    if (mkdtemp(directory) == NULL) return 1;
    if (snprintf(file, sizeof(file), "%s/alpha", directory) >=
            (int)sizeof(file) ||
        snprintf(link_path, sizeof(link_path), "%s/link", directory) >=
            (int)sizeof(link_path) ||
        snprintf(subdirectory, sizeof(subdirectory), "%s/subdir", directory) >=
            (int)sizeof(subdirectory) ||
        snprintf(child, sizeof(child), "%s/child", subdirectory) >=
            (int)sizeof(child) ||
        snprintf(extra, sizeof(extra), "%s/extra", subdirectory) >=
            (int)sizeof(extra) ||
        snprintf(symlink_root, sizeof(symlink_root), "%s/symlink-root",
                 directory) >= (int)sizeof(symlink_root) ||
        snprintf(symlink_target, sizeof(symlink_target), "%s/target",
                 symlink_root) >= (int)sizeof(symlink_target) ||
        snprintf(symlink_other, sizeof(symlink_other), "%s/other",
                 symlink_root) >= (int)sizeof(symlink_other) ||
        snprintf(symlink_one, sizeof(symlink_one), "%s/link-one",
                 symlink_root) >= (int)sizeof(symlink_one) ||
        snprintf(symlink_two, sizeof(symlink_two), "%s/link-two",
                 symlink_root) >= (int)sizeof(symlink_two) ||
        snprintf(symlink_directory, sizeof(symlink_directory), "%s/real-dir",
                 symlink_root) >= (int)sizeof(symlink_directory) ||
        snprintf(symlink_child, sizeof(symlink_child), "%s/child",
                 symlink_directory) >= (int)sizeof(symlink_child) ||
        snprintf(symlink_dir_link, sizeof(symlink_dir_link), "%s/dir-link",
                 symlink_root) >= (int)sizeof(symlink_dir_link) ||
        write_file(file, "observed\n") < 0 ||
        symlink("alpha", link_path) < 0 || mkdir(subdirectory, 0700) < 0 ||
        write_file(child, "member\n") < 0 || mkdir(symlink_root, 0700) < 0 ||
        write_file(symlink_target, "symlink target\n") < 0 ||
        write_file(symlink_other, "alternate target\n") < 0 ||
        mkdir(symlink_directory, 0700) < 0 ||
        write_file(symlink_child, "directory link target\n") < 0 ||
        symlink("link-two", symlink_one) < 0 ||
        symlink("target", symlink_two) < 0 ||
        symlink("real-dir", symlink_dir_link) < 0) {
        perror("observed-input fixture setup failed");
        goto done;
    }
    root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) goto done;

    report.observation_complete = 1;
    report.stable_input_view = 1;
    report.candidate_count = 7;
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
    snprintf(report.candidates[4].kind,
             sizeof(report.candidates[4].kind), "directory listing");
    snprintf(report.candidates[4].path,
             sizeof(report.candidates[4].path), "subdir");
    snprintf(report.candidates[5].kind,
             sizeof(report.candidates[5].kind), "cwd change");
    snprintf(report.candidates[5].path,
             sizeof(report.candidates[5].path), "subdir");
    snprintf(report.candidates[6].kind,
             sizeof(report.candidates[6].kind), "opened file");
    snprintf(report.candidates[6].path,
             sizeof(report.candidates[6].path), "link");

    if (tm_observer_capture_inputs(&report, root, &manifest) < 0 ||
        manifest.count != 4 ||
        strcmp(manifest.items[0].path, "alpha") != 0 ||
        manifest.items[0].kind != TM_INPUT_FILE ||
        strncmp(manifest.items[0].digest, "sha256:", 7) != 0 ||
        strcmp(manifest.items[1].path, "link") != 0 ||
        manifest.items[1].kind != TM_INPUT_SYMLINK ||
        strcmp(manifest.items[1].target, "alpha") != 0 ||
        strcmp(manifest.items[2].path, "not-created") != 0 ||
        manifest.items[2].kind != TM_INPUT_EXISTS ||
        manifest.items[2].exists != 0 ||
        strcmp(manifest.items[3].path, "subdir") != 0 ||
        manifest.items[3].kind != TM_INPUT_DIRECTORY ||
        strncmp(manifest.items[3].digest, "sha256:", 7) != 0) {
        fprintf(stderr, "observed candidates were not captured canonically\n");
        goto done;
    }
    if (tm_input_matches(root, &manifest.items[3]) != 0 ||
        write_file(extra, "new member\n") < 0 ||
        tm_input_matches(root, &manifest.items[3]) == 0) {
        fprintf(stderr, "directory membership did not invalidate its digest\n");
        goto done;
    }
    if (tm_input_matches(root, &manifest.items[1]) != 0 ||
        unlink(link_path) < 0 || symlink("subdir/child", link_path) < 0 ||
        tm_input_matches(root, &manifest.items[1]) != 1) {
        fprintf(stderr, "symlink target change did not invalidate its input\n");
        goto done;
    }
    tm_observed_input_manifest_clear(&manifest);

    if (tm_snapshot_create(root, symlink_snapshot_paths, 1, &snapshot) < 0 ||
        (symlink_snapshot_root = tm_snapshot_open_root_readable(
            snapshot, 0)) < 0) {
        perror("symlink snapshot create failed");
        goto done;
    }
    snapshot_roots[0] = symlink_snapshot_root;
    report.candidate_count = 2;
    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "opened file");
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path),
             "symlink-root/link-one");
    snprintf(report.candidates[1].kind,
             sizeof(report.candidates[1].kind), "opened file");
    snprintf(report.candidates[1].path,
             sizeof(report.candidates[1].path),
             "symlink-root/dir-link/child");
    if (tm_observer_capture_snapshot_inputs(&report,
            symlink_snapshot_paths, snapshot_roots, 1, &manifest) < 0 ||
        manifest.count != 5 ||
        strcmp(manifest.items[0].path, "symlink-root/dir-link") != 0 ||
        manifest.items[0].kind != TM_INPUT_SYMLINK ||
        strcmp(manifest.items[0].target, "real-dir") != 0 ||
        strcmp(manifest.items[1].path, "symlink-root/link-one") != 0 ||
        manifest.items[1].kind != TM_INPUT_SYMLINK ||
        strcmp(manifest.items[1].target, "link-two") != 0 ||
        strcmp(manifest.items[2].path, "symlink-root/link-two") != 0 ||
        manifest.items[2].kind != TM_INPUT_SYMLINK ||
        strcmp(manifest.items[2].target, "target") != 0 ||
        strcmp(manifest.items[3].path, "symlink-root/real-dir/child") != 0 ||
        manifest.items[3].kind != TM_INPUT_FILE ||
        strcmp(manifest.items[4].path, "symlink-root/target") != 0 ||
        manifest.items[4].kind != TM_INPUT_FILE ||
        tm_observed_inputs_match_snapshots(manifest.items, manifest.count,
            symlink_snapshot_paths, snapshot_roots, 1) != 0) {
        fprintf(stderr,
            "snapshot input capture did not record a symlink chain and target\n");
        goto done;
    }
    if (write_file(symlink_target, "changed target\n") < 0 ||
        tm_snapshot_create(root, symlink_snapshot_paths, 1,
                           &changed_snapshot) < 0 ||
        (changed_snapshot_root = tm_snapshot_open_root_readable(
            changed_snapshot, 0)) < 0) {
        perror("changed symlink snapshot setup failed");
        goto done;
    }
    snapshot_roots[0] = changed_snapshot_root;
    if (tm_observed_inputs_match_snapshots(manifest.items, manifest.count,
            symlink_snapshot_paths, snapshot_roots, 1) != 1) {
        fprintf(stderr, "symlink target content change was not detected\n");
        goto done;
    }
    close(changed_snapshot_root);
    changed_snapshot_root = -1;
    tm_snapshot_free(changed_snapshot);
    changed_snapshot = NULL;
    snapshot_roots[0] = symlink_snapshot_root;
    if (tm_observer_capture_snapshot_inputs(&report,
            symlink_snapshot_paths, snapshot_roots, 1, &manifest) < 0 ||
        unlink(symlink_one) < 0 || symlink("other", symlink_one) < 0 ||
        tm_snapshot_create(root, symlink_snapshot_paths, 1,
                           &changed_snapshot) < 0 ||
        (changed_snapshot_root = tm_snapshot_open_root_readable(
            changed_snapshot, 0)) < 0) {
        perror("changed symlink target setup failed");
        goto done;
    }
    snapshot_roots[0] = changed_snapshot_root;
    if (tm_observed_inputs_match_snapshots(manifest.items, manifest.count,
            symlink_snapshot_paths, snapshot_roots, 1) != 1) {
        fprintf(stderr, "symlink target change was not detected\n");
        goto done;
    }
    tm_observed_input_manifest_clear(&manifest);
    close(changed_snapshot_root);
    changed_snapshot_root = -1;
    tm_snapshot_free(changed_snapshot);
    changed_snapshot = NULL;
    close(symlink_snapshot_root);
    symlink_snapshot_root = -1;
    tm_snapshot_free(snapshot);
    snapshot = NULL;

    if (snprintf(symlink_escape, sizeof(symlink_escape), "%s/escape",
                 symlink_root) >= (int)sizeof(symlink_escape) ||
        snprintf(symlink_absolute, sizeof(symlink_absolute), "%s/absolute",
                 symlink_root) >= (int)sizeof(symlink_absolute) ||
        symlink("../outside", symlink_escape) < 0 ||
        symlink("/etc/passwd", symlink_absolute) < 0) {
        perror("unsafe symlink fixture setup failed");
        goto done;
    }
    for (chain_index = 0;
         chain_index <= TM_OBSERVED_INPUT_MAX_SYMLINKS; chain_index++) {
        char link_name[64], next_name[64];
        int length = snprintf(link_name, sizeof(link_name), "long-%02zu",
                              chain_index);
        if (length < 0 || (size_t)length >= sizeof(link_name) ||
            snprintf(symlink_chain[chain_index],
                     sizeof(symlink_chain[chain_index]), "%s/%s",
                     symlink_root, link_name) >=
                (int)sizeof(symlink_chain[chain_index])) {
            errno = ENAMETOOLONG;
            goto done;
        }
        if (chain_index < TM_OBSERVED_INPUT_MAX_SYMLINKS) {
            length = snprintf(next_name, sizeof(next_name), "long-%02zu",
                              chain_index + 1);
            if (length < 0 || (size_t)length >= sizeof(next_name)) {
                errno = ENAMETOOLONG;
                goto done;
            }
        } else {
            strcpy(next_name, "target");
        }
        if (symlink(next_name, symlink_chain[chain_index]) < 0) {
            perror("long symlink chain setup failed");
            goto done;
        }
    }
    report.candidate_count = 1;
    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "opened file");
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path), "symlink-root/escape");
    if (tm_observer_capture_inputs(&report, root, &manifest) == 0) {
        tm_observed_input_manifest_clear(&manifest);
        fprintf(stderr, "parent-escaping symlink was accepted\n");
        goto done;
    }
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path), "symlink-root/absolute");
    if (tm_observer_capture_inputs(&report, root, &manifest) == 0) {
        tm_observed_input_manifest_clear(&manifest);
        fprintf(stderr, "absolute symlink was accepted\n");
        goto done;
    }
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path), "symlink-root/long-00");
    if (tm_observer_capture_inputs(&report, root, &manifest) == 0) {
        tm_observed_input_manifest_clear(&manifest);
        fprintf(stderr, "over-limit symlink chain was accepted\n");
        goto done;
    }

    if (tm_snapshot_create(root, snapshot_paths, 1, &snapshot) < 0 ||
        (snapshot_root = tm_snapshot_open_root(snapshot, 0)) < 0 ||
        write_file(child, "changed after snapshot\n") < 0) goto done;
    snapshot_roots[0] = snapshot_root;
    report.candidate_count = 2;
    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "directory listing");
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path), "subdir");
    snprintf(report.candidates[1].kind,
             sizeof(report.candidates[1].kind), "opened file");
    snprintf(report.candidates[1].path,
             sizeof(report.candidates[1].path), "subdir/child");
    if (tm_observer_capture_snapshot_inputs(&report, snapshot_paths,
            snapshot_roots, 1, &manifest) < 0 || manifest.count != 2 ||
        strcmp(manifest.items[0].path, "subdir") != 0 ||
        manifest.items[0].kind != TM_INPUT_DIRECTORY ||
        strcmp(manifest.items[1].path, "subdir/child") != 0 ||
        manifest.items[1].kind != TM_INPUT_FILE ||
        tm_input_capture_directory_root(snapshot_root, snapshot_digest) < 0 ||
        strcmp(snapshot_digest, manifest.items[0].digest) != 0 ||
        tm_input_capture_file(snapshot_root, "child", snapshot_digest) < 0 ||
        strcmp(snapshot_digest, manifest.items[1].digest) != 0 ||
        tm_observed_inputs_match_snapshots(manifest.items, manifest.count,
            snapshot_paths, snapshot_roots, 1) != 0 ||
        tm_input_matches(root, &manifest.items[1]) == 0) {
        fprintf(stderr, "snapshot input manifest did not retain consumed bytes\n");
        goto done;
    }
    {
        struct tm_input_observation altered[2] = {
            manifest.items[0], manifest.items[1]
        };
        char altered_digest[72];
        memcpy(altered_digest, manifest.items[1].digest,
               sizeof(altered_digest));
        altered_digest[7] = altered_digest[7] == '0' ? '1' : '0';
        altered[1].digest = altered_digest;
        if (tm_observed_inputs_match_snapshots(altered,
                manifest.count, snapshot_paths, snapshot_roots, 1) != 1) {
            fprintf(stderr, "snapshot matcher accepted a changed digest\n");
            goto done;
        }
    }
    tm_observed_input_manifest_clear(&manifest);
    close(snapshot_root);
    snapshot_root = -1;
    tm_snapshot_free(snapshot);
    snapshot = NULL;

    if (tm_snapshot_create(root, file_snapshot_paths, 1, &snapshot) < 0) {
        perror("file snapshot create failed");
        goto done;
    }
    snapshot_root = tm_snapshot_open_root_readable(snapshot, 0);
    if (snapshot_root < 0) {
        perror("file snapshot open failed");
        goto done;
    }
    if (write_file(file, "changed after file snapshot\n") < 0) {
        perror("file snapshot mutate failed");
        goto done;
    }
    snapshot_roots[0] = snapshot_root;
    report.candidate_count = 1;
    snprintf(report.candidates[0].kind,
             sizeof(report.candidates[0].kind), "opened file");
    snprintf(report.candidates[0].path,
             sizeof(report.candidates[0].path), "alpha");
    if (tm_observer_capture_snapshot_inputs(&report, file_snapshot_paths,
            snapshot_roots, 1, &manifest) < 0 || manifest.count != 1 ||
        tm_input_capture_file_root(snapshot_root, snapshot_digest) < 0 ||
        strcmp(snapshot_digest, manifest.items[0].digest) != 0 ||
        lseek(snapshot_root, 0, SEEK_CUR) != 0 ||
        tm_observed_inputs_match_snapshots(manifest.items, manifest.count,
            file_snapshot_paths, snapshot_roots, 1) != 0 ||
        tm_input_matches(root, &manifest.items[0]) == 0) {
        fprintf(stderr, "file-root snapshot manifest lost consumed bytes (count=%zu, digest=%s, snapshot=%s, match=%d)\n",
            manifest.count, manifest.count == 0 ? "-" : manifest.items[0].digest,
            snapshot_digest, manifest.count == 0 ? -2 :
                tm_input_matches(root, &manifest.items[0]));
        goto done;
    }
    tm_observed_input_manifest_clear(&manifest);
    close(snapshot_root);
    snapshot_root = -1;
    tm_snapshot_free(snapshot);
    snapshot = NULL;

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
    if (changed_snapshot_root >= 0) close(changed_snapshot_root);
    if (symlink_snapshot_root >= 0) close(symlink_snapshot_root);
    if (snapshot_root >= 0) close(snapshot_root);
    tm_snapshot_free(snapshot);
    tm_snapshot_free(changed_snapshot);
    if (root >= 0) close(root);
    unlink(link_path);
    unlink(child);
    unlink(extra);
    rmdir(subdirectory);
    unlink(symlink_one);
    unlink(symlink_two);
    unlink(symlink_dir_link);
    unlink(symlink_escape);
    unlink(symlink_absolute);
    for (chain_index = 0;
         chain_index <= TM_OBSERVED_INPUT_MAX_SYMLINKS; chain_index++)
        unlink(symlink_chain[chain_index]);
    unlink(symlink_child);
    rmdir(symlink_directory);
    unlink(symlink_target);
    unlink(symlink_other);
    rmdir(symlink_root);
    unlink(file);
    rmdir(directory);
    return status;
}
