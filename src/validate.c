#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "tm/result.h"
#include "tm/trust.h"
#include "tm/validate.h"

#define RECORD_LIMIT (16U * 1024U * 1024U)

static const char *status_name(enum tm_trust_status status)
{
    switch (status) {
    case TM_TRUST_APPROVED: return "trusted";
    case TM_TRUST_REVOKED: return "revoked";
    case TM_TRUST_UNKNOWN_REPOSITORY:
    case TM_TRUST_UNKNOWN_KEY: return "unknown";
    case TM_TRUST_UNAPPROVED_PROFILE:
    case TM_TRUST_STALE_EPOCH:
    case TM_TRUST_UNSUPPORTED_SEMANTICS: return "untrusted";
    case TM_TRUST_POLICY_ERROR: return "policy-error";
    }
    return "unknown";
}

static int read_record(int directory, const char *name,
                       unsigned char **bytes, size_t *length)
{
    struct stat before, after;
    unsigned char *data;
    size_t used = 0;
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (fstat(fd, &before) < 0 || !S_ISREG(before.st_mode) ||
        before.st_size < 2 || (uint64_t)before.st_size > RECORD_LIMIT) {
        close(fd); errno = EINVAL; return -1;
    }
    data = malloc((size_t)before.st_size);
    if (data == NULL) { close(fd); return -1; }
    while (used < (size_t)before.st_size) {
        ssize_t count = read(fd, data + used, (size_t)before.st_size - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { free(data); close(fd); errno = EIO; return -1; }
        used += (size_t)count;
    }
    if (fstat(fd, &after) < 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec ||
        before.st_mtim.tv_nsec != after.st_mtim.tv_nsec) {
        free(data); close(fd); errno = EBUSY; return -1;
    }
    close(fd); *bytes = data; *length = used; return 0;
}

static int id_directory(const char *name)
{
    size_t i;
    if (strlen(name) != 64) return 0;
    for (i = 0; i < 64; i++)
        if (!((name[i] >= '0' && name[i] <= '9') ||
              (name[i] >= 'a' && name[i] <= 'f'))) return 0;
    return 1;
}

static int directory_at(int parent, const char *name)
{
    struct stat st;
    return fstatat(parent, name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISDIR(st.st_mode);
}

static char *discover_root(void)
{
    char *current = realpath(".", NULL);
    if (current == NULL) return NULL;
    for (;;) {
        char marker[PATH_MAX];
        struct stat st;
        int n = snprintf(marker, sizeof(marker), "%s/.git", current);
        if (n > 0 && (size_t)n < sizeof(marker) && lstat(marker, &st) == 0 &&
            (S_ISDIR(st.st_mode) || S_ISREG(st.st_mode))) return current;
        if (strcmp(current, "/") == 0) return current;
        char *slash = strrchr(current, '/');
        if (slash == NULL) return current;
        if (slash == current) current[1] = '\0';
        else *slash = '\0';
    }
}

static int check_filename(const char *name, const struct tm_result_summary *s,
                          const char *record_id)
{
    char expected[200];
    int n = snprintf(expected, sizeof(expected), "%s-%s-%s.tm.json",
                     s->command_id, s->verification_id, record_id + 7);
    return n > 0 && (size_t)n < sizeof(expected) && strcmp(name, expected) == 0;
}

static int validate_one(int dirfd, const char *name, const char *command_id,
                        const char *verification_id,
                        const struct tm_trust_policy *policy, int require_trust,
                        unsigned long counts[7])
{
    unsigned char *bytes = NULL;
    size_t length = 0;
    char record_id[72];
    struct tm_result_summary summary = {0};
    EVP_PKEY *key = NULL;
    enum tm_trust_status trust = TM_TRUST_UNKNOWN_KEY;
    struct tm_result_policy verify_policy;
    int valid = 0;

    if (read_record(dirfd, name, &bytes, &length) < 0) {
        if (errno == ELOOP || errno == EINVAL || errno == EFBIG) goto done;
        valid = -1;
        goto done;
    }
    if (tm_result_inspect(bytes, length, &summary, record_id) < 0 ||
        strcmp(summary.command_id, command_id) != 0 ||
        strcmp(summary.verification_id, verification_id) != 0 ||
        !check_filename(name, &summary, record_id)) goto done;
    if (policy != NULL) {
        trust = tm_trust_policy_classify(policy, summary.repository_id,
            summary.profile_digest, summary.key_id, summary.trust_epoch,
            summary.semantics_version, &key);
        if (key != NULL) {
            verify_policy = (struct tm_result_policy){summary.repository_id,
                summary.profile_digest, 0, summary.verification_fingerprint};
            if (tm_result_verify(bytes, length, key, &verify_policy,
                                 record_id) < 0) goto done;
        }
    }
    if (trust == TM_TRUST_POLICY_ERROR) goto done;
    if (require_trust && trust != TM_TRUST_APPROVED) {
        fprintf(stderr, "tm validate: %s: %s (trust required)\n", name,
                status_name(trust));
        valid = 2;
        goto done;
    }
    printf("%s: valid, %s\n", name, status_name(trust));
    counts[trust <= TM_TRUST_POLICY_ERROR ? (unsigned long)trust : 6]++;
    valid = 1;
done:
    if (valid == 0) fprintf(stderr, "tm validate: %s: invalid record\n", name);
    if (valid == -1) fprintf(stderr, "tm validate: %s: %s\n", name,
                             strerror(errno));
    EVP_PKEY_free(key);
    tm_result_summary_clear(&summary);
    free(bytes);
    return valid;
}

int tm_validate_main(int argc, char **argv)
{
    const char *root_arg = NULL, *policy_path = NULL;
    char *root = NULL;
    struct tm_trust_policy *policy = NULL;
    int require_trust = 0, rootfd = -1, tmfd = -1, resultsfd = -1, rc = 0;
    int i, saw_invalid = 0;
    unsigned long counts[8] = {0};
    DIR *commands = NULL;
    struct dirent *command_entry;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--require-trust") == 0) require_trust = 1;
        else if ((strcmp(argv[i], "--root") == 0 ||
                  strcmp(argv[i], "--trust-policy") == 0) && i + 1 < argc) {
            if (strcmp(argv[i], "--root") == 0) root_arg = argv[++i];
            else policy_path = argv[++i];
        } else {
            fprintf(stderr, "Usage: tm validate [--root DIR] [--trust-policy FILE] [--require-trust]\n");
            return 125;
        }
    }
    root = root_arg == NULL ? discover_root() : realpath(root_arg, NULL);
    if (root == NULL) { perror("tm validate: root"); return 125; }
    if (policy_path != NULL && tm_trust_policy_load(policy_path, &policy) < 0) {
        perror("tm validate: trust policy"); free(root); return 125;
    }
    rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0) { perror("tm validate: root"); rc = 125; goto done; }
    if (!directory_at(rootfd, ".tm")) goto done;
    tmfd = openat(rootfd, ".tm", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (tmfd < 0) { perror("tm validate: .tm"); rc = 125; goto done; }
    if (!directory_at(tmfd, "results")) goto done;
    resultsfd = openat(tmfd, "results", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (resultsfd < 0) {
        perror("tm validate: results"); rc = 125;
        goto done;
    }
    commands = fdopendir(dup(resultsfd));
    if (commands == NULL) { perror("tm validate: results"); rc = 125; goto done; }
    while ((command_entry = readdir(commands)) != NULL) {
        int commandfd;
        DIR *verifications;
        struct dirent *verification_entry;
        if (!id_directory(command_entry->d_name)) continue;
        if (!directory_at(resultsfd, command_entry->d_name)) continue;
        commandfd = openat(resultsfd, command_entry->d_name,
                           O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (commandfd < 0) { rc = 125; continue; }
        verifications = fdopendir(dup(commandfd));
        if (verifications == NULL) { close(commandfd); rc = 125; continue; }
        while ((verification_entry = readdir(verifications)) != NULL) {
            int verifyfd;
            DIR *records;
            struct dirent *record_entry;
            if (!id_directory(verification_entry->d_name) ||
                !directory_at(commandfd, verification_entry->d_name)) continue;
            verifyfd = openat(commandfd, verification_entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (verifyfd < 0) { rc = 125; continue; }
            records = fdopendir(dup(verifyfd));
            if (records == NULL) { close(verifyfd); rc = 125; continue; }
            while ((record_entry = readdir(records)) != NULL) {
                int result;
                size_t n = strlen(record_entry->d_name);
                if (n < 8 || strcmp(record_entry->d_name + n - 8, ".tm.json") != 0) continue;
                result = validate_one(verifyfd, record_entry->d_name,
                    command_entry->d_name, verification_entry->d_name,
                    policy, require_trust, counts);
                if (result == 0) saw_invalid = 1;
                if (result == 2) saw_invalid = 1;
                if (result == -1) rc = 125;
            }
            closedir(records); close(verifyfd);
        }
        closedir(verifications); close(commandfd);
    }
    printf("tm validate: trusted=%lu untrusted=%lu revoked=%lu\n",
           counts[TM_TRUST_APPROVED],
           counts[TM_TRUST_UNKNOWN_KEY] + counts[TM_TRUST_UNKNOWN_REPOSITORY] +
           counts[TM_TRUST_UNAPPROVED_PROFILE] + counts[TM_TRUST_STALE_EPOCH] +
           counts[TM_TRUST_UNSUPPORTED_SEMANTICS], counts[TM_TRUST_REVOKED]);
    if (rc == 0 && saw_invalid) rc = 1;
done:
    if (commands != NULL) closedir(commands);
    if (resultsfd >= 0) close(resultsfd);
    if (tmfd >= 0) close(tmfd);
    if (rootfd >= 0) close(rootfd);
    tm_trust_policy_free(policy);
    free(root);
    return rc;
}
