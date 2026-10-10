#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "tm/result.h"
#include "tm/identity.h"
#include "tm/trust.h"

static int test_store(const unsigned char *record, size_t length,
                      const char *expected_id,
                      const struct tm_trust_policy *trust)
{
    char root[] = "/tmp/tm-result-store-XXXXXX";
    char clone[] = "/tmp/tm-result-clone-XXXXXX";
    char shared_store[] = "/tmp/tm-result-shared-XXXXXX";
    char outside[] = "/tmp/tm-result-outside-XXXXXX";
    char filename[80], path[512];
    struct tm_result_summary summary = {0};
    char record_id[72];
    struct stat st;
    unsigned char *stored = NULL;
    unsigned char *found = NULL;
    size_t used = 0;
    size_t found_length = 0;
    int rootfd = -1, clonefd = -1, sharedfd = -1, tmfd = -1;
    int resultsfd = -1, commandfd = -1;
    int verifyfd = -1, fd = -1, result = -1;
    if (mkdtemp(root) == NULL || mkdtemp(clone) == NULL ||
        mkdtemp(shared_store) == NULL ||
        mkdtemp(outside) == NULL) goto done;
    rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0 || tm_result_inspect(record, length, &summary, record_id) < 0 ||
        strcmp(record_id, expected_id) != 0 ||
        mkdirat(rootfd, "tests", 0700) < 0) goto done;
    fd = openat(rootfd, "tests/a", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                0600);
    if (fd < 0) goto done;
    { int opened = fd; fd = -1; if (close(opened) < 0) goto done; }
    if (
        tm_result_store(rootfd, record, length, record_id) != 0 ||
        tm_result_store(rootfd, record, length, record_id) != 0 ||
        snprintf(filename, sizeof(filename), "%s.tm.json", record_id + 7) >=
            (int)sizeof(filename)) goto done;
    if (tm_result_find(rootfd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.verification_fingerprint, trust, &found, &found_length,
            record_id) != 0 || found_length != length ||
        memcmp(found, record, length) != 0 || strcmp(record_id, expected_id) != 0)
        goto done;
    free(found); found = NULL;
    if (tm_result_find_matching_inputs(rootfd, rootfd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.profile_digest,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            trust, &found, &found_length, record_id) != 0 ||
        found_length != length || strcmp(record_id, expected_id) != 0)
        goto done;
    free(found); found = NULL;
    if (tm_result_find_matching_inputs(rootfd, rootfd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.profile_digest,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            trust, &found, &found_length, record_id) != 1 || found != NULL)
        goto done;
    /* The same portable evidence is discoverable from another checkout root. */
    clonefd = open(clone, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (clonefd < 0 || mkdirat(clonefd, "tests", 0700) < 0) goto done;
    fd = openat(clonefd, "tests/a", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                0600);
    if (fd < 0) goto done;
    { int opened = fd; fd = -1; if (close(opened) < 0) goto done; }
    sharedfd = open(shared_store, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (sharedfd < 0 || tm_result_store(sharedfd, record, length, record_id) != 0 ||
        tm_result_find_in_store(sharedfd, clonefd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.verification_fingerprint, trust, &found, &found_length,
            record_id) != 0 || found_length != length ||
        memcmp(found, record, length) != 0 || strcmp(record_id, expected_id) != 0)
        goto done;
    free(found); found = NULL;
    if (tm_result_find_matching_inputs(sharedfd, clonefd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.profile_digest,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            trust, &found, &found_length, record_id) != 0 ||
        found_length != length || strcmp(record_id, expected_id) != 0)
        goto done;
    free(found); found = NULL;
    fd = openat(clonefd, "tests/a", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write(fd, "changed", 7) != 7) goto done;
    { int opened = fd; fd = -1; if (close(opened) < 0) goto done; }
    if (tm_result_find_matching_inputs(sharedfd, clonefd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.profile_digest,
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            trust, &found, &found_length, record_id) != 1 || found != NULL)
        goto done;
    if (tm_result_find_in_store(sharedfd, clonefd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.verification_fingerprint, trust, &found, &found_length,
            record_id) != 1 || found != NULL) goto done;
    fd = openat(clonefd, "tests/a", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) goto done;
    { int opened = fd; fd = -1; if (close(opened) < 0) goto done; }
    close(sharedfd); sharedfd = -1;
    close(clonefd); clonefd = -1;
    fd = openat(rootfd, "tests/a", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0 || write(fd, "changed", 7) != 7) goto done;
    { int opened = fd; fd = -1; if (close(opened) < 0) goto done; }
    if (tm_result_find(rootfd,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            summary.verification_fingerprint, trust, &found, &found_length,
            record_id) != 1 || found != NULL) goto done;
    fd = openat(rootfd, "tests/a", O_WRONLY | O_TRUNC | O_CLOEXEC);
    if (fd < 0) goto done;
    { int opened = fd; fd = -1; if (close(opened) < 0) goto done; }
    tmfd = openat(rootfd, ".tm", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (tmfd < 0) goto done;
    resultsfd = openat(tmfd, "results", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (resultsfd < 0) goto done;
    commandfd = openat(resultsfd, summary.command_id,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (commandfd < 0) goto done;
    verifyfd = openat(commandfd, summary.verification_id,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (verifyfd < 0) goto done;
    {
        size_t index;
        char filler[32];
        for (index = 0; index < 257; index++) {
            int filler_fd;
            if (snprintf(filler, sizeof(filler), "unrelated-%03zu", index) >=
                (int)sizeof(filler)) goto done;
            filler_fd = openat(verifyfd, filler,
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (filler_fd < 0 || close(filler_fd) < 0) goto done;
        }
        if (tm_result_find(rootfd,
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                summary.verification_fingerprint, trust, &found,
                &found_length, record_id) != -1 || found != NULL) goto done;
        for (index = 0; index < 257; index++) {
            (void)snprintf(filler, sizeof(filler), "unrelated-%03zu", index);
            if (unlinkat(verifyfd, filler, 0) < 0) goto done;
        }
    }
    fd = openat(verifyfd, filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0777) != 0644 || st.st_size != (off_t)length) goto done;
    stored = malloc(length);
    if (stored == NULL) goto done;
    while (used < length) {
        ssize_t n = read(fd, stored + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        used += (size_t)n;
    }
    if (memcmp(stored, record, length) != 0) goto done;
    close(fd); fd = -1;
    fd = openat(verifyfd, filename, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || write(fd, "x", 1) != 1) goto done;
    close(fd); fd = -1;
    if (tm_result_store(rootfd, record, length, record_id) == 0) goto done;

    /* Refuse a symlink at the repository-controlled .tm boundary. */
    close(verifyfd); verifyfd = -1;
    close(commandfd); commandfd = -1;
    close(resultsfd); resultsfd = -1;
    close(tmfd); tmfd = -1;
    /* Use a second root to isolate the symlink test. */
    {
        char symlink_root[] = "/tmp/tm-result-link-XXXXXX";
        int linkfd;
        if (mkdtemp(symlink_root) == NULL) goto done;
        linkfd = open(symlink_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (linkfd < 0 || symlink(outside, strcat(strcpy(path, symlink_root), "/.tm")) < 0) {
            if (linkfd >= 0) close(linkfd);
            rmdir(symlink_root);
            goto done;
        }
        if (tm_result_store(linkfd, record, length, record_id) == 0) {
            close(linkfd); unlink(path); rmdir(symlink_root); goto done;
        }
        close(linkfd); unlink(path); rmdir(symlink_root);
    }
    result = 0;
done:
    if (fd >= 0) close(fd);
    free(found);
    if (clonefd >= 0) close(clonefd);
    if (sharedfd >= 0) close(sharedfd);
    if (verifyfd >= 0) close(verifyfd);
    if (commandfd >= 0) close(commandfd);
    if (resultsfd >= 0) close(resultsfd);
    if (tmfd >= 0) close(tmfd);
    if (rootfd >= 0) close(rootfd);
    if (summary.command_id[0] != '\0' && summary.verification_id[0] != '\0') {
        snprintf(path, sizeof(path), "%s/.tm/results/%s/%s/%s.tm.json",
                 root, summary.command_id, summary.verification_id, expected_id + 7);
        unlink(path);
        snprintf(path, sizeof(path), "%s/.tm/results/%s/%s", root,
                 summary.command_id, summary.verification_id); rmdir(path);
        snprintf(path, sizeof(path), "%s/.tm/results/%s", root,
                 summary.command_id); rmdir(path);
        snprintf(path, sizeof(path), "%s/.tm/results", root); rmdir(path);
        snprintf(path, sizeof(path), "%s/.tm", root); rmdir(path);
    }
    snprintf(path, sizeof(path), "%s/.tm", root);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/tests/a", root); unlink(path);
    snprintf(path, sizeof(path), "%s/tests", root); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm/results/%s/%s/%s.tm.json",
             clone, summary.command_id, summary.verification_id, expected_id + 7);
    unlink(path);
    snprintf(path, sizeof(path), "%s/.tm/results/%s/%s", clone,
             summary.command_id, summary.verification_id); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm/results/%s", clone,
             summary.command_id); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm/results", clone); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm", clone); rmdir(path);
    snprintf(path, sizeof(path), "%s/tests/a", clone); unlink(path);
    snprintf(path, sizeof(path), "%s/tests", clone); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm/results/%s/%s/%s.tm.json",
             shared_store, summary.command_id, summary.verification_id,
             expected_id + 7);
    unlink(path);
    snprintf(path, sizeof(path), "%s/.tm/results/%s/%s", shared_store,
             summary.command_id, summary.verification_id); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm/results/%s", shared_store,
             summary.command_id); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm/results", shared_store); rmdir(path);
    snprintf(path, sizeof(path), "%s/.tm", shared_store); rmdir(path);
    rmdir(root); rmdir(outside);
    rmdir(clone);
    rmdir(shared_store);
    free(stored);
    tm_result_summary_clear(&summary);
    return result;
}

static int test_output_lookup(
    const struct tm_verification_identity *identity, EVP_PKEY *private_key,
    const struct tm_trust_policy *trust)
{
    const char *argv[] = {"make", "test"};
    const char *input_paths[] = {"tests/a", "tests/missing"};
    char root[] = "/tmp/tm-result-output-XXXXXX";
    char shared_store[] = "/tmp/tm-result-output-shared-XXXXXX";
    char path[768], record_id[72] = {0};
    const char *roots[] = {"dist"};
    char command_fingerprint[72], verification_fingerprint[72];
    struct tm_command_identity command_identity = {
        "sample", argv, 2, "subdir", input_paths, 2, roots, 1
    };
    struct tm_verification_identity output_identity = *identity;
    struct tm_output_manifest manifest = {0};
    unsigned char *record = NULL, *found = NULL;
    size_t record_length = 0, found_length = 0;
    char blob_digest[72] = {0};
    int rootfd = -1, sharedfd = -1, testsfd = -1, distfd = -1, filefd = -1;
    int result = -1;
    if (tm_command_fingerprint(&command_identity, command_fingerprint) < 0)
        goto done;
    output_identity.command_fingerprint = command_fingerprint;
    if (tm_verification_fingerprint(&output_identity,
                                    verification_fingerprint) < 0) goto done;
    if (mkdtemp(root) == NULL || mkdtemp(shared_store) == NULL) goto done;
    rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    sharedfd = open(shared_store, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0 || sharedfd < 0 || mkdirat(rootfd, "tests", 0700) < 0 ||
        mkdirat(rootfd, "dist", 0700) < 0) goto done;
    testsfd = openat(rootfd, "tests", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    distfd = openat(rootfd, "dist", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (testsfd < 0 || distfd < 0) goto done;
    filefd = openat(testsfd, "a", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (filefd < 0 || close(filefd) < 0) { filefd = -1; goto done; }
    filefd = -1;
    filefd = openat(distfd, "report.txt", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (filefd < 0 || write(filefd, "artifact", 8) != 8 || close(filefd) < 0) {
        filefd = -1; goto done;
    }
    filefd = -1;
    if (tm_outputs_capture_to_store(rootfd, sharedfd, roots, 1, &manifest) < 0 ||
        tm_result_create_with_outputs(&output_identity, 3, private_key, &manifest,
            &record, &record_length, record_id) < 0 ||
        tm_result_store(sharedfd, record, record_length, record_id) < 0)
        goto done;
    if (manifest.count != 2) goto done;
    memcpy(blob_digest, manifest.entries[1].digest, sizeof(blob_digest));
    if (tm_result_find(rootfd, command_fingerprint, verification_fingerprint,
            trust, &found, &found_length, record_id) != 1 || found != NULL)
        goto done;
    if (unlinkat(distfd, "report.txt", 0) < 0 ||
        (filefd = openat(distfd, "stale.txt",
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) < 0 ||
        write(filefd, "stale", 5) != 5 || close(filefd) < 0) {
        filefd = -1; goto done;
    }
    filefd = -1;
    close(distfd); distfd = -1;
    if (tm_result_find_and_restore_in_store(sharedfd, rootfd,
            command_fingerprint,
            verification_fingerprint,
            trust, roots, 1, &found, &found_length, record_id) != 0 ||
        found_length != record_length || memcmp(found, record, record_length) != 0)
        goto done;
    distfd = openat(rootfd, "dist", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (distfd < 0 ||
        fstatat(distfd, "stale.txt", &(struct stat){0}, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) goto done;
    filefd = openat(distfd, "report.txt", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    {
        char bytes[8];
        if (filefd < 0 || read(filefd, bytes, sizeof(bytes)) != sizeof(bytes) ||
            memcmp(bytes, "artifact", sizeof(bytes)) != 0) goto done;
    }
    result = 0;
done:
    if (filefd >= 0) close(filefd);
    if (rootfd >= 0) close(rootfd);
    if (sharedfd >= 0) close(sharedfd);
    if (testsfd >= 0) close(testsfd);
    if (distfd >= 0) close(distfd);
    free(found);
    free(record);
    tm_output_manifest_clear(&manifest);
    if (root[0] != '\0') {
        char result_dir[768], command_dir[768], record_path[768];
        (void)snprintf(path, sizeof(path), "%s/tests/a", root); (void)unlink(path);
        (void)snprintf(path, sizeof(path), "%s/tests", root); (void)rmdir(path);
        (void)snprintf(path, sizeof(path), "%s/dist/report.txt", root); (void)unlink(path);
        (void)snprintf(path, sizeof(path), "%s/dist/stale.txt", root); (void)unlink(path);
        (void)snprintf(path, sizeof(path), "%s/dist", root); (void)rmdir(path);
        if (blob_digest[0] != '\0') {
            (void)snprintf(path, sizeof(path), "%s/.tm/blobs/sha256/%s", shared_store, blob_digest + 7);
            (void)unlink(path);
        }
        (void)snprintf(path, sizeof(path), "%s/.tm/blobs/sha256", shared_store); (void)rmdir(path);
        (void)snprintf(path, sizeof(path), "%s/.tm/blobs", shared_store); (void)rmdir(path);
        (void)snprintf(command_dir, sizeof(command_dir), "%s/.tm/results/%s",
                       root, command_fingerprint + 7);
        (void)snprintf(result_dir, sizeof(result_dir),
            "%s/.tm/results/%s/%s", shared_store, command_fingerprint + 7,
            verification_fingerprint + 7);
        (void)snprintf(record_path, sizeof(record_path),
            "%s/.tm/results/%s/%s/%s.tm.json", shared_store,
            command_fingerprint + 7, verification_fingerprint + 7,
            record_id[0] == '\0' ? "" : record_id + 7);
        (void)unlink(record_path); (void)rmdir(result_dir); (void)rmdir(command_dir);
        (void)snprintf(path, sizeof(path), "%s/.tm/results", shared_store); (void)rmdir(path);
        (void)snprintf(path, sizeof(path), "%s/.tm", shared_store); (void)rmdir(path);
        (void)rmdir(root);
        (void)rmdir(shared_store);
    }
    return result;
}

static int must_reject(const unsigned char *record, size_t length,
                       EVP_PKEY *key, const struct tm_result_policy *policy)
{
    char record_id[72];
    return tm_result_verify(record, length, key, policy, record_id) != 0;
}

int main(void)
{
    static const unsigned char seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    const struct tm_input_observation inputs[] = {
        {"tests/missing", TM_INPUT_EXISTS, NULL, NULL, 0},
        {"tests/a", TM_INPUT_FILE,
         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         NULL, 0},
        {"tests/a", TM_INPUT_FILE,
         "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         NULL, 0}
    };
    struct tm_verification_identity identity = {
        "sample",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "subdir",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        inputs, 3
    };
    const struct tm_result_policy policy = {
        "sample",
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        3,
        "sha256:ba299d5d7bd04d93e635617e6d2e496248711a9fa93bf4360a98c706ad201622"
    };
    const char *expected_id =
        "sha256:1b7606c1405e680b8c0ccc04144fb3600f385dc4825b2581e4d0282e13f7c1ea";
    EVP_PKEY *private_key = EVP_PKEY_new_raw_private_key_ex(
        NULL, "ED25519", NULL, seed, sizeof(seed));
    unsigned char *record = NULL;
    unsigned char *tampered = NULL;
    unsigned char *noncanonical = NULL;
    size_t record_length = 0;
    char record_id[72];
    char verified_id[72];
    struct tm_result_summary summary = {0};
    const char *signature_marker = "\"signature\":\"";
    char *signature_text;
    struct tm_trust_policy *trust = NULL;
    char policy_path[] = "/tmp/tm-result-policy-XXXXXX";
    char input_root[] = "/tmp/tm-result-inputs-XXXXXX";
    char input_directory[256];
    char input_file[256];
    char policy_json[2048];
    unsigned char public_bytes[32];
    size_t public_length = sizeof(public_bytes);
    unsigned char public_b64[EVP_ENCODE_LENGTH(32)];
    int policy_fd = -1, input_root_fd = -1, input_file_fd = -1;
    int policy_length;
    int public_b64_length;

    if (private_key == NULL ||
        tm_result_create(&identity, 3, private_key, &record, &record_length,
                         record_id) != 0) goto fail;
    if (strcmp(record_id, expected_id) != 0) {
        fprintf(stderr, "signed result record ID changed: %s\n", record_id);
        goto fail;
    }
    if (
        record[record_length - 1] != '\n' ||
        tm_result_verify(record, record_length, private_key, &policy,
                         verified_id) != 0 ||
        strcmp(verified_id, expected_id) != 0 ||
        tm_result_inspect(record, record_length, &summary, verified_id) != 0 ||
        strcmp(summary.tm_version, "0.1") != 0 ||
        strcmp(summary.repository_id, "sample") != 0 ||
        strcmp(summary.profile_digest,
               "sha256:1111111111111111111111111111111111111111111111111111111111111111") != 0 ||
        strcmp(summary.runtime_digest,
               "sha256:2222222222222222222222222222222222222222222222222222222222222222") != 0 ||
        strcmp(summary.context_digest,
               "sha256:3333333333333333333333333333333333333333333333333333333333333333") != 0 ||
        strcmp(summary.command_id,
               "0000000000000000000000000000000000000000000000000000000000000000") != 0 ||
        strcmp(summary.verification_id,
               "ba299d5d7bd04d93e635617e6d2e496248711a9fa93bf4360a98c706ad201622") != 0 ||
        summary.input_count != 2 ||
        strcmp(summary.inputs[0].path, "tests/a") != 0 ||
        strcmp(summary.inputs[1].path, "tests/missing") != 0 ||
        strcmp(verified_id, expected_id) != 0) {
        fprintf(stderr, "signed result golden vector failed\n");
        goto fail;
    }
    tampered = malloc(record_length);
    if (tampered == NULL) goto fail;
    memcpy(tampered, record, record_length);
    {
        char *tool_version = strstr((char *)tampered,
                                    "\"tm_version\":\"0.1\"");
        if (tool_version == NULL) goto fail;
        tool_version[strlen("\"tm_version\":\"")] = 'x';
        if (tm_result_inspect(tampered, record_length, &summary,
                              verified_id) == 0) {
            tm_result_summary_clear(&summary);
            fprintf(stderr, "invalid sidecar producer version was accepted\n");
            goto fail;
        }
    }
    free(tampered);
    tampered = NULL;
    tm_result_summary_clear(&summary);
    {
        struct tm_output_entry entries[] = {
            {"dist", TM_OUTPUT_DIRECTORY, 0755, "", 0},
            {"dist/report.txt", TM_OUTPUT_FILE, 0644,
             "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 3}
        };
        struct tm_output_manifest manifest = {entries, 2};
        unsigned char *output_record = NULL;
        size_t output_length = 0;
        char output_id[72];
        if (tm_result_create_with_outputs(&identity, 3, private_key, &manifest,
                &output_record, &output_length, output_id) != 0 ||
            tm_result_verify(output_record, output_length, private_key, &policy,
                             verified_id) != 0 ||
            tm_result_inspect(output_record, output_length, &summary,
                              verified_id) != 0 || summary.output_count != 2 ||
            strcmp(summary.outputs[1].path, "dist/report.txt") != 0 ||
            summary.outputs[1].size != 3) {
            free(output_record);
            tm_result_summary_clear(&summary);
            fprintf(stderr, "signed output manifest failed\n");
            goto fail;
        }
        tm_result_summary_clear(&summary);
        free(output_record);
    }
    {
        const struct tm_input_observation ordered_inputs[] = {
            {"tests/a", TM_INPUT_FILE,
             "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             NULL, 0},
            {"tests/z", TM_INPUT_FILE,
             "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
             NULL, 0}
        };
        struct tm_verification_identity ordered_identity = identity;
        unsigned char *ordering_record = NULL;
        size_t ordering_length = 0;
        char ordering_id[72];
        char *path_a;
        char *path_z;
        ordered_identity.inputs = ordered_inputs;
        ordered_identity.input_count = 2;
        if (tm_result_create(&ordered_identity, 3, private_key,
                             &ordering_record, &ordering_length,
                             ordering_id) != 0) goto fail;
        path_a = strstr((char *)ordering_record, "\"path\":\"tests/a\"");
        path_z = strstr((char *)ordering_record, "\"path\":\"tests/z\"");
        if (path_a == NULL || path_z == NULL) {
            free(ordering_record);
            goto fail;
        }
        path_a += strlen("\"path\":\"tests/");
        path_z += strlen("\"path\":\"tests/");
        *path_a = 'z';
        *path_z = 'a';
        if (tm_result_inspect(ordering_record, ordering_length,
                              &summary, ordering_id) == 0) {
            tm_result_summary_clear(&summary);
            free(ordering_record);
            fprintf(stderr, "unsorted result inputs were accepted\n");
            goto fail;
        }
        free(ordering_record);
    }
    if (EVP_PKEY_get_raw_public_key(private_key, public_bytes,
                                    &public_length) != 1 ||
        public_length != sizeof(public_bytes)) goto fail;
    public_b64_length = EVP_EncodeBlock(public_b64, public_bytes,
                                        sizeof(public_bytes));
    if (public_b64_length != 44) goto fail;
    public_b64[public_b64_length] = '\0';
    policy_length = snprintf(policy_json, sizeof(policy_json),
        "{\"schema_version\":1,\"repositories\":[{"
        "\"repository_id\":\"sample\",\"minimum_trust_epoch\":3,"
        "\"allowed_semantics\":[2],"
        "\"profiles\":[\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"],"
        "\"keys\":[{\"key_id\":\"sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9\","
        "\"public_key\":\"%s\",\"role\":\"test\"}],\"revoked_key_ids\":[]}]}",
        public_b64);
    if (policy_length < 0 || policy_length >= (int)sizeof(policy_json)) goto fail;
    policy_fd = mkstemp(policy_path);
    if (policy_fd < 0) goto fail;
    if (write(policy_fd, policy_json, (size_t)policy_length) != policy_length) {
        close(policy_fd);
        policy_fd = -1;
        goto fail;
    }
    if (close(policy_fd) < 0) {
        policy_fd = -1;
        goto fail;
    }
    policy_fd = -1;
    if (tm_trust_policy_load(policy_path, &trust) != 0 ||
        tm_result_verify_trusted(record, record_length, trust,
                                 policy.expected_verification_fingerprint,
                                 verified_id) != 0 ||
        strcmp(verified_id, expected_id) != 0) {
        fprintf(stderr, "operator-policy result verification failed\n");
        goto fail;
    }
    if (tm_result_verify_trusted(
            record, record_length, trust,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            verified_id) == 0) {
        fprintf(stderr, "trusted verifier ignored current fingerprint\n");
        goto fail;
    }
    if (test_store(record, record_length, expected_id, trust) != 0) {
        fprintf(stderr, "portable result storage/lookup checks failed\n");
        goto fail;
    }
    if (test_output_lookup(&identity, private_key, trust) != 0) {
        fprintf(stderr, "trusted output result restore lookup failed\n");
        goto fail;
    }

    if (mkdtemp(input_root) == NULL) goto fail;
    snprintf(input_directory, sizeof(input_directory), "%s/tests", input_root);
    snprintf(input_file, sizeof(input_file), "%s/tests/a", input_root);
    if (mkdir(input_directory, 0700) < 0) goto fail;
    input_file_fd = open(input_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (input_file_fd < 0) goto fail;
    {
        int fd = input_file_fd;
        input_file_fd = -1;
        if (close(fd) < 0) goto fail;
    }
    input_root_fd = open(input_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (input_root_fd < 0 ||
        tm_result_verify_inputs_match(record, record_length, trust,
                                      input_root_fd, verified_id) != 0) {
        fprintf(stderr, "signed record input manifest did not match\n");
        goto fail;
    }
    input_file_fd = open(input_file, O_WRONLY | O_TRUNC);
    if (input_file_fd < 0 || write(input_file_fd, "changed", 7) != 7)
        goto fail;
    {
        int fd = input_file_fd;
        input_file_fd = -1;
        if (close(fd) < 0) goto fail;
    }
    if (tm_result_verify_inputs_match(record, record_length, trust,
                                      input_root_fd, verified_id) != 1) {
        fprintf(stderr, "signed record input change was not detected\n");
        goto fail;
    }
    if (tm_result_verify_inputs_match(tampered, record_length, trust,
                                      input_root_fd, verified_id) == 0) {
        fprintf(stderr, "tampered signed record passed trusted input check\n");
        goto fail;
    }

    tampered = malloc(record_length + 1);
    noncanonical = malloc(record_length + 2);
    if (tampered == NULL || noncanonical == NULL) goto fail;
    memcpy(tampered, record, record_length + 1);
    signature_text = strstr((char *)tampered, signature_marker);
    if (signature_text == NULL) goto fail;
    signature_text += strlen(signature_marker);
    signature_text[0] = signature_text[0] == 'A' ? 'B' : 'A';
    if (!must_reject(tampered, record_length, private_key, &policy)) {
        fprintf(stderr, "tampered signature was accepted\n");
        goto fail;
    }
    if (tm_result_inspect(tampered, record_length, &summary, verified_id) != 0) {
        fprintf(stderr, "structural inspection required a trusted signature\n");
        goto fail;
    }
    tm_result_summary_clear(&summary);

    noncanonical[0] = ' ';
    memcpy(noncanonical + 1, record, record_length);
    noncanonical[record_length + 1] = '\0';
    if (!must_reject(noncanonical, record_length + 1, private_key, &policy)) {
        fprintf(stderr, "noncanonical signed record was accepted\n");
        goto fail;
    }
    if (!must_reject(record, record_length - 1, private_key, &policy)) {
        fprintf(stderr, "record without required LF was accepted\n");
        goto fail;
    }

    {
        struct tm_result_policy wrong = policy;
        wrong.repository_id = "another-project";
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
        wrong = policy;
        wrong.approved_profile_digest =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
        wrong = policy;
        wrong.minimum_trust_epoch = 4;
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
        wrong = policy;
        wrong.expected_verification_fingerprint =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        if (!must_reject(record, record_length, private_key, &wrong)) goto fail;
    }

    free(tampered);
    free(noncanonical);
    free(record);
    tm_result_summary_clear(&summary);
    tm_trust_policy_free(trust);
    unlink(policy_path);
    if (input_root_fd >= 0) close(input_root_fd);
    unlink(input_file);
    rmdir(input_directory);
    rmdir(input_root);
    EVP_PKEY_free(private_key);
    return 0;

fail:
    free(tampered);
    free(noncanonical);
    free(record);
    tm_result_summary_clear(&summary);
    if (policy_fd >= 0) close(policy_fd);
    if (input_file_fd >= 0) close(input_file_fd);
    if (input_root_fd >= 0) close(input_root_fd);
    tm_trust_policy_free(trust);
    unlink(policy_path);
    unlink(input_file);
    rmdir(input_directory);
    rmdir(input_root);
    EVP_PKEY_free(private_key);
    return 1;
}
