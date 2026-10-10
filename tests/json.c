#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tm/json.h"

static int expect_canonical(const char *source, const char *expected)
{
    struct tm_json_value *value = NULL;
    unsigned char *canonical = NULL;
    size_t length = 0;
    int result = 0;

    if (tm_json_parse((const unsigned char *)source, strlen(source), &value) != 0 ||
        tm_json_canonicalize(value, &canonical, &length) != 0 ||
        length != strlen(expected) || memcmp(canonical, expected, length) != 0) {
        fprintf(stderr, "JSON canonicalization vector failed: %s\n", source);
    } else {
        result = 1;
    }
    free(canonical);
    tm_json_free(value);
    return result;
}

static int expect_rejected(const char *source)
{
    struct tm_json_value *value = NULL;
    int accepted = tm_json_parse((const unsigned char *)source, strlen(source),
                                 &value) == 0;
    tm_json_free(value);
    if (accepted) {
        fprintf(stderr, "JSON parser accepted invalid input: %s\n", source);
    }
    return !accepted;
}

int main(void)
{
    if (!expect_canonical("{ \"z\": 1, \"a\": \"\\n\" }",
                          "{\"a\":\"\\n\",\"z\":1}") ||
        !expect_canonical("{\"\":2,\"𐀀\":1}",
                          "{\"𐀀\":1,\"\":2}") ||
        !expect_rejected("{\"a\":1,\"a\":2}") ||
        !expect_rejected("{\"a\":1.0}") ||
        !expect_rejected("{\"a\":-1}") ||
        !expect_rejected("{\"a\":9007199254740992}") ||
        !expect_rejected("{\"a\":\"\\uD800\"}") ||
        !expect_rejected("{\"a\":\"\\u0000\"}")) {
        return 1;
    }
    return 0;
}
