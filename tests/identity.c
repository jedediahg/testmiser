#include <stdio.h>
#include <string.h>

#include "tm/identity.h"

int main(void)
{
    const char *argv[] = {"./test.sh", ""};
    const char *inputs_a[] = {"data/a", "src/z", "data/a"};
    const char *inputs_b[] = {"src/z", "data/a"};
    const char *outputs[] = {"reports/test.xml", "reports/test.xml"};
    const char *different_argv[] = {"./test.sh"};
    const char *escaped_argv[] = {"./test.sh", "line\nbreak"};
    struct tm_command_identity identity = {
        "sample", argv, 2, ".", inputs_a, 3, outputs, 2
    };
    struct tm_command_identity reordered = {
        "sample", argv, 2, ".", inputs_b, 2, outputs, 1
    };
    struct tm_command_identity changed = {
        "sample", different_argv, 1, ".", inputs_b, 2, outputs, 1
    };
    const char *unsafe_inputs[] = {"../outside"};
    struct tm_command_identity unsafe = {
        "sample", argv, 2, ".", unsafe_inputs, 1, NULL, 0
    };
    struct tm_command_identity escaped = {
        "sample", escaped_argv, 2, ".", (const char *const[]){"data/a"}, 1,
        (const char *const[]){"reports/test.xml"}, 1
    };
    const char *expected =
        "sha256:15a4e25fc2f3692c7b9974235819c63f3fe4c87c2870b526262a8c6b43e782b1";
    char fingerprint[72];
    char second[72];

    if (tm_command_fingerprint(&identity, fingerprint) != 0 ||
        strcmp(fingerprint, expected) != 0) {
        fprintf(stderr, "command fingerprint golden vector failed\n");
        return 1;
    }
    if (tm_command_fingerprint(&reordered, second) != 0 ||
        strcmp(fingerprint, second) != 0) {
        fprintf(stderr, "declaration sorting/deduplication failed\n");
        return 1;
    }
    if (tm_command_fingerprint(&changed, second) != 0 ||
        strcmp(fingerprint, second) == 0) {
        fprintf(stderr, "argv boundary did not change command identity\n");
        return 1;
    }
    if (tm_command_fingerprint(&unsafe, second) == 0) {
        fprintf(stderr, "path traversal entered command identity\n");
        return 1;
    }
    if (tm_command_fingerprint(&escaped, second) != 0 ||
        strcmp(second,
               "sha256:080e1aa178cc3cd16df93fda97cbeaf7b82afce7806969326ffd628218c5f89b") != 0) {
        fprintf(stderr, "JCS control-character escaping vector failed\n");
        return 1;
    }
    return 0;
}
