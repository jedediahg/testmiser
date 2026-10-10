#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tm/json.h"

#define JSON_MAX_BYTES (1024U * 1024U)
#define JSON_MAX_NODES 65536U
#define JSON_MAX_DEPTH 64U
#define JSON_MAX_INTEGER UINT64_C(9007199254740991)
#define JSON_MAX_MEMBERS 1024U

struct member {
    char *key;
    struct tm_json_value *value;
};
struct tm_json_value {
    enum tm_json_type type;
    union {
        int boolean;
        uint64_t integer;
        char *string;
        struct { struct tm_json_value **items; size_t count, capacity; } array;
        struct { struct member *items; size_t count, capacity; } object;
    } data;
};
struct buffer { unsigned char *data; size_t length, capacity; };
struct parser { const unsigned char *data; size_t length, position, nodes; };

static int utf8_valid(const unsigned char *text)
{
    while (*text != 0) {
        unsigned int first = *text++, count, minimum, codepoint, i;
        if (first < 0x80) continue;
        if (first >= 0xc2 && first <= 0xdf) {
            count = 1; minimum = 0x80; codepoint = first & 0x1f;
        } else if (first >= 0xe0 && first <= 0xef) {
            count = 2; minimum = 0x800; codepoint = first & 0x0f;
        } else if (first >= 0xf0 && first <= 0xf4) {
            count = 3; minimum = 0x10000; codepoint = first & 0x07;
        } else return 0;
        for (i = 0; i < count; i++) {
            unsigned int next = *text++;
            if (next == 0 || (next & 0xc0) != 0x80) return 0;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if (codepoint < minimum || codepoint > 0x10ffff ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff)) return 0;
    }
    return 1;
}

static struct tm_json_value *new_value(enum tm_json_type type)
{
    struct tm_json_value *value = calloc(1, sizeof(*value));
    if (value != NULL) value->type = type;
    return value;
}
struct tm_json_value *tm_json_new_null(void) { return new_value(TM_JSON_NULL); }
struct tm_json_value *tm_json_new_boolean(int b)
{
    struct tm_json_value *v = new_value(TM_JSON_BOOLEAN);
    if (v != NULL) v->data.boolean = b != 0;
    return v;
}
struct tm_json_value *tm_json_new_integer(uint64_t n)
{
    struct tm_json_value *v;
    if (n > JSON_MAX_INTEGER) { errno = ERANGE; return NULL; }
    v = new_value(TM_JSON_INTEGER);
    if (v != NULL) v->data.integer = n;
    return v;
}
struct tm_json_value *tm_json_new_string(const char *s)
{
    struct tm_json_value *v;
    if (s == NULL || !utf8_valid((const unsigned char *)s)) {
        errno = EILSEQ; return NULL;
    }
    v = new_value(TM_JSON_STRING);
    if (v == NULL) return NULL;
    v->data.string = strdup(s);
    if (v->data.string == NULL) { free(v); errno = ENOMEM; return NULL; }
    return v;
}
struct tm_json_value *tm_json_new_array(void) { return new_value(TM_JSON_ARRAY); }
struct tm_json_value *tm_json_new_object(void) { return new_value(TM_JSON_OBJECT); }

void tm_json_free(struct tm_json_value *v)
{
    size_t i;
    if (v == NULL) return;
    if (v->type == TM_JSON_STRING) free(v->data.string);
    if (v->type == TM_JSON_ARRAY) {
        for (i = 0; i < v->data.array.count; i++) tm_json_free(v->data.array.items[i]);
        free(v->data.array.items);
    }
    if (v->type == TM_JSON_OBJECT) {
        for (i = 0; i < v->data.object.count; i++) {
            free(v->data.object.items[i].key);
            tm_json_free(v->data.object.items[i].value);
        }
        free(v->data.object.items);
    }
    free(v);
}

static int grow(void **items, size_t *capacity, size_t count, size_t item_size)
{
    size_t next = *capacity == 0 ? 8 : *capacity * 2;
    void *memory;
    if (count < *capacity) return 0;
    if (next > SIZE_MAX / item_size) { errno = EOVERFLOW; return -1; }
    memory = realloc(*items, next * item_size);
    if (memory == NULL) { errno = ENOMEM; return -1; }
    *items = memory;
    *capacity = next;
    return 0;
}
int tm_json_array_append(struct tm_json_value *a, struct tm_json_value *v)
{
    if (a == NULL || a->type != TM_JSON_ARRAY || v == NULL ||
        grow((void **)&a->data.array.items, &a->data.array.capacity,
             a->data.array.count, sizeof(*a->data.array.items)) < 0) {
        errno = EINVAL; return -1;
    }
    a->data.array.items[a->data.array.count++] = v;
    return 0;
}
int tm_json_object_set(struct tm_json_value *o, const char *key,
                       struct tm_json_value *v)
{
    size_t i;
    char *copy;
    if (o == NULL || o->type != TM_JSON_OBJECT || key == NULL || v == NULL ||
        !utf8_valid((const unsigned char *)key)) { errno = EINVAL; return -1; }
    for (i = 0; i < o->data.object.count; i++) {
        if (strcmp(o->data.object.items[i].key, key) == 0) {
            errno = EEXIST; return -1;
        }
    }
    if (o->data.object.count >= JSON_MAX_MEMBERS) { errno = E2BIG; return -1; }
    if (grow((void **)&o->data.object.items, &o->data.object.capacity,
             o->data.object.count, sizeof(*o->data.object.items)) < 0) return -1;
    copy = strdup(key);
    if (copy == NULL) { errno = ENOMEM; return -1; }
    o->data.object.items[o->data.object.count].key = copy;
    o->data.object.items[o->data.object.count].value = v;
    o->data.object.count++;
    return 0;
}

enum tm_json_type tm_json_typeof(const struct tm_json_value *v)
{ return v == NULL ? TM_JSON_NULL : v->type; }
const struct tm_json_value *tm_json_object_get(const struct tm_json_value *o,
                                                const char *key)
{
    size_t i;
    if (o == NULL || o->type != TM_JSON_OBJECT || key == NULL) return NULL;
    for (i = 0; i < o->data.object.count; i++)
        if (strcmp(o->data.object.items[i].key, key) == 0)
            return o->data.object.items[i].value;
    return NULL;
}
const struct tm_json_value *tm_json_array_get(const struct tm_json_value *a,
                                               size_t i)
{
    if (a == NULL || a->type != TM_JSON_ARRAY || i >= a->data.array.count)
        return NULL;
    return a->data.array.items[i];
}
size_t tm_json_size(const struct tm_json_value *v)
{
    if (v == NULL) return 0;
    if (v->type == TM_JSON_ARRAY) return v->data.array.count;
    if (v->type == TM_JSON_OBJECT) return v->data.object.count;
    return 0;
}
const char *tm_json_string_value(const struct tm_json_value *v)
{ return v != NULL && v->type == TM_JSON_STRING ? v->data.string : NULL; }
uint64_t tm_json_integer_value(const struct tm_json_value *v)
{ return v != NULL && v->type == TM_JSON_INTEGER ? v->data.integer : UINT64_MAX; }
int tm_json_boolean_value(const struct tm_json_value *v)
{ return v != NULL && v->type == TM_JSON_BOOLEAN && v->data.boolean; }

static void whitespace(struct parser *p)
{
    while (p->position < p->length) {
        unsigned char c = p->data[p->position];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
        p->position++;
    }
}
static struct tm_json_value *parse_value(struct parser *p, unsigned int depth);

static int append(struct buffer *b, const void *data, size_t length)
{
    size_t needed, cap;
    unsigned char *memory;
    if (length == 0) return 0;
    if (data == NULL) { errno = EINVAL; return -1; }
    if (length > SIZE_MAX - b->length) { errno = EOVERFLOW; return -1; }
    needed = b->length + length;
    if (needed > b->capacity || b->data == NULL) {
        cap = b->capacity == 0 ? 32 : b->capacity;
        while (cap < needed) {
            if (cap > SIZE_MAX / 2) { cap = needed; break; }
            cap *= 2;
        }
        memory = realloc(b->data, cap);
        if (memory == NULL) { errno = ENOMEM; return -1; }
        b->data = memory; b->capacity = cap;
    }
    memcpy(b->data + b->length, data, length);
    b->length += length;
    return 0;
}
static int append_cp(struct buffer *b, uint32_t cp)
{
    unsigned char out[4]; size_t n;
    if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
        errno = EILSEQ; return -1;
    }
    if (cp < 0x80) { out[0] = (unsigned char)cp; n = 1; }
    else if (cp < 0x800) {
        out[0] = (unsigned char)(0xc0 | (cp >> 6));
        out[1] = (unsigned char)(0x80 | (cp & 63)); n = 2;
    } else if (cp < 0x10000) {
        out[0] = (unsigned char)(0xe0 | (cp >> 12));
        out[1] = (unsigned char)(0x80 | ((cp >> 6) & 63));
        out[2] = (unsigned char)(0x80 | (cp & 63)); n = 3;
    } else {
        out[0] = (unsigned char)(0xf0 | (cp >> 18));
        out[1] = (unsigned char)(0x80 | ((cp >> 12) & 63));
        out[2] = (unsigned char)(0x80 | ((cp >> 6) & 63));
        out[3] = (unsigned char)(0x80 | (cp & 63)); n = 4;
    }
    return append(b, out, n);
}
static int hex(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int hex4(struct parser *p, uint32_t *out)
{
    unsigned int i; uint32_t v = 0;
    if (p->length - p->position < 4) return -1;
    for (i = 0; i < 4; i++) {
        int d = hex(p->data[p->position++]);
        if (d < 0) return -1;
        v = (v << 4) | (uint32_t)d;
    }
    *out = v; return 0;
}
static char *parse_string(struct parser *p)
{
    struct buffer b = {0}; char *result;
    if (p->position >= p->length || p->data[p->position++] != '"') return NULL;
    while (p->position < p->length) {
        unsigned char c = p->data[p->position++];
        if (c == '"') {
            if (append(&b, "", 1) < 0 || !utf8_valid(b.data)) {
                free(b.data); return NULL;
            }
            result = (char *)b.data; return result;
        }
        if (c < 0x20) { free(b.data); return NULL; }
        if (c != '\\') {
            if (append(&b, &c, 1) < 0) { free(b.data); return NULL; }
            continue;
        }
        if (p->position >= p->length) { free(b.data); return NULL; }
        c = p->data[p->position++];
        if (c == '"' || c == '\\' || c == '/') {
            if (append(&b, &c, 1) < 0) { free(b.data); return NULL; }
        } else if (c == 'b' || c == 'f' || c == 'n' || c == 'r' || c == 't') {
            c = c == 'b' ? '\b' : c == 'f' ? '\f' : c == 'n' ? '\n' :
                c == 'r' ? '\r' : '\t';
            if (append(&b, &c, 1) < 0) { free(b.data); return NULL; }
        } else if (c == 'u') {
            uint32_t cp;
            if (hex4(p, &cp) < 0) { free(b.data); return NULL; }
            if (cp >= 0xd800 && cp <= 0xdbff) {
                uint32_t low;
                if (p->length - p->position < 6 ||
                    p->data[p->position++] != '\\' ||
                    p->data[p->position++] != 'u' || hex4(p, &low) < 0 ||
                    low < 0xdc00 || low > 0xdfff) {
                    free(b.data); return NULL;
                }
                cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
            }
            if (append_cp(&b, cp) < 0) { free(b.data); return NULL; }
        } else { free(b.data); return NULL; }
    }
    free(b.data); return NULL;
}
static struct tm_json_value *parse_array(struct parser *p, unsigned int depth)
{
    struct tm_json_value *a = tm_json_new_array();
    if (a == NULL) return NULL;
    p->position++; whitespace(p);
    if (p->position < p->length && p->data[p->position] == ']') {
        p->position++; return a;
    }
    for (;;) {
        struct tm_json_value *v = parse_value(p, depth + 1);
        if (v == NULL || tm_json_array_append(a, v) < 0) {
            tm_json_free(v); tm_json_free(a); return NULL;
        }
        whitespace(p);
        if (p->position >= p->length) { tm_json_free(a); return NULL; }
        if (p->data[p->position] == ']') { p->position++; return a; }
        if (p->data[p->position++] != ',') { tm_json_free(a); return NULL; }
        whitespace(p);
    }
}
static struct tm_json_value *parse_object(struct parser *p, unsigned int depth)
{
    struct tm_json_value *o = tm_json_new_object();
    if (o == NULL) return NULL;
    p->position++; whitespace(p);
    if (p->position < p->length && p->data[p->position] == '}') {
        p->position++; return o;
    }
    for (;;) {
        char *key = parse_string(p); struct tm_json_value *v;
        if (key == NULL) { tm_json_free(o); return NULL; }
        whitespace(p);
        if (p->position >= p->length || p->data[p->position++] != ':') {
            free(key); tm_json_free(o); return NULL;
        }
        whitespace(p); v = parse_value(p, depth + 1);
        if (v == NULL || tm_json_object_set(o, key, v) < 0) {
            free(key); tm_json_free(v); tm_json_free(o); return NULL;
        }
        free(key); whitespace(p);
        if (p->position >= p->length) { tm_json_free(o); return NULL; }
        if (p->data[p->position] == '}') { p->position++; return o; }
        if (p->data[p->position++] != ',') { tm_json_free(o); return NULL; }
        whitespace(p);
    }
}
static struct tm_json_value *parse_number(struct parser *p)
{
    uint64_t n = 0; size_t start = p->position;
    if (p->data[p->position] == '0') {
        p->position++;
        if (p->position < p->length && p->data[p->position] >= '0' &&
            p->data[p->position] <= '9') return NULL;
    } else {
        while (p->position < p->length && p->data[p->position] >= '0' &&
               p->data[p->position] <= '9') {
            unsigned int d = p->data[p->position++] - '0';
            if (n > (JSON_MAX_INTEGER - d) / 10) { errno = ERANGE; return NULL; }
            n = n * 10 + d;
        }
    }
    if (p->position == start || (p->position < p->length &&
        (p->data[p->position] == '.' || p->data[p->position] == 'e' ||
         p->data[p->position] == 'E' || p->data[p->position] == '-'))) return NULL;
    return tm_json_new_integer(n);
}
static struct tm_json_value *parse_value(struct parser *p, unsigned int depth)
{
    unsigned char c;
    if (depth > JSON_MAX_DEPTH || ++p->nodes > JSON_MAX_NODES) {
        errno = E2BIG; return NULL;
    }
    whitespace(p);
    if (p->position >= p->length) return NULL;
    c = p->data[p->position];
    if (c == '{') return parse_object(p, depth);
    if (c == '[') return parse_array(p, depth);
    if (c == '"') {
        char *s = parse_string(p); struct tm_json_value *v;
        if (s == NULL) return NULL;
        v = new_value(TM_JSON_STRING);
        if (v == NULL) { free(s); return NULL; }
        v->data.string = s; return v;
    }
    if (c >= '0' && c <= '9') return parse_number(p);
    if (p->length - p->position >= 4 &&
        memcmp(p->data + p->position, "true", 4) == 0) {
        p->position += 4; return tm_json_new_boolean(1);
    }
    if (p->length - p->position >= 5 &&
        memcmp(p->data + p->position, "false", 5) == 0) {
        p->position += 5; return tm_json_new_boolean(0);
    }
    if (p->length - p->position >= 4 &&
        memcmp(p->data + p->position, "null", 4) == 0) {
        p->position += 4; return tm_json_new_null();
    }
    return NULL;
}
int tm_json_parse(const unsigned char *data, size_t length,
                  struct tm_json_value **output)
{
    struct parser p; struct tm_json_value *v;
    if (data == NULL || output == NULL || length == 0 ||
        length > JSON_MAX_BYTES) { errno = EINVAL; return -1; }
    p = (struct parser){data, length, 0, 0};
    v = parse_value(&p, 0);
    if (v == NULL) return -1;
    whitespace(&p);
    if (p.position != length) { tm_json_free(v); errno = EINVAL; return -1; }
    *output = v; return 0;
}

struct utf16_cursor { const unsigned char *p; uint16_t low; int has_low; };
static int utf16_next(struct utf16_cursor *c, uint16_t *unit)
{
    uint32_t cp; unsigned int a;
    if (c->has_low) { c->has_low = 0; *unit = c->low; return 1; }
    if (*c->p == 0) return 0;
    a = *c->p++;
    if (a < 0x80) cp = a;
    else if (a < 0xe0) { cp = (a & 31) << 6; cp |= *c->p++ & 63; }
    else if (a < 0xf0) {
        cp = (a & 15) << 12; cp |= (*c->p++ & 63) << 6; cp |= *c->p++ & 63;
    } else {
        cp = (a & 7) << 18; cp |= (*c->p++ & 63) << 12;
        cp |= (*c->p++ & 63) << 6; cp |= *c->p++ & 63;
    }
    if (cp <= 0xffff) *unit = (uint16_t)cp;
    else {
        cp -= 0x10000; *unit = (uint16_t)(0xd800 + (cp >> 10));
        c->low = (uint16_t)(0xdc00 + (cp & 1023)); c->has_low = 1;
    }
    return 1;
}
static int utf16_compare(const char *a, const char *b)
{
    struct utf16_cursor ac = {(const unsigned char *)a, 0, 0};
    struct utf16_cursor bc = {(const unsigned char *)b, 0, 0};
    for (;;) {
        uint16_t au = 0, bu = 0; int ah = utf16_next(&ac, &au);
        int bh = utf16_next(&bc, &bu);
        if (!ah || !bh) return ah - bh;
        if (au != bu) return au < bu ? -1 : 1;
    }
}
static int append_string(struct buffer *b, const char *s)
{
    static const char hexes[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)s;
    if (append(b, "\"", 1) < 0) return -1;
    while (*p != 0) {
        unsigned char c = *p++; char esc[6];
        if (c == '"' || c == '\\') {
            esc[0] = '\\'; esc[1] = (char)c;
            if (append(b, esc, 2) < 0) return -1;
        } else if (c == '\b' || c == '\t' || c == '\n' || c == '\f' || c == '\r') {
            esc[0] = '\\'; esc[1] = c == '\b' ? 'b' : c == '\t' ? 't' :
                c == '\n' ? 'n' : c == '\f' ? 'f' : 'r';
            if (append(b, esc, 2) < 0) return -1;
        } else if (c < 0x20) {
            esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
            esc[4] = hexes[c >> 4]; esc[5] = hexes[c & 15];
            if (append(b, esc, 6) < 0) return -1;
        } else if (append(b, &c, 1) < 0) return -1;
    }
    return append(b, "\"", 1);
}
static int canonical(const struct tm_json_value *v, struct buffer *b,
                     unsigned int depth)
{
    size_t i;
    if (depth > JSON_MAX_DEPTH) { errno = E2BIG; return -1; }
    switch (v->type) {
    case TM_JSON_NULL: return append(b, "null", 4);
    case TM_JSON_BOOLEAN:
        return v->data.boolean ? append(b, "true", 4) : append(b, "false", 5);
    case TM_JSON_INTEGER: {
        char n[32]; int len = snprintf(n, sizeof(n), "%" PRIu64, v->data.integer);
        return len < 0 ? -1 : append(b, n, (size_t)len);
    }
    case TM_JSON_STRING: return append_string(b, v->data.string);
    case TM_JSON_ARRAY:
        if (append(b, "[", 1) < 0) return -1;
        for (i = 0; i < v->data.array.count; i++) {
            if ((i && append(b, ",", 1) < 0) ||
                canonical(v->data.array.items[i], b, depth + 1) < 0) return -1;
        }
        return append(b, "]", 1);
    case TM_JSON_OBJECT: {
        size_t *order = v->data.object.count == 0 ? NULL :
            malloc(v->data.object.count * sizeof(*order));
        if (v->data.object.count > 0 && order == NULL) { errno = ENOMEM; return -1; }
        for (i = 0; i < v->data.object.count; i++) order[i] = i;
        for (i = 1; i < v->data.object.count; i++) {
            size_t current = order[i], at = i;
            while (at > 0 && utf16_compare(v->data.object.items[order[at - 1]].key,
                                           v->data.object.items[current].key) > 0) {
                order[at] = order[at - 1]; at--;
            }
            order[at] = current;
        }
        if (append(b, "{", 1) < 0) { free(order); return -1; }
        for (i = 0; i < v->data.object.count; i++) {
            const struct member *m = &v->data.object.items[order[i]];
            if ((i && append(b, ",", 1) < 0) || append_string(b, m->key) < 0 ||
                append(b, ":", 1) < 0 || canonical(m->value, b, depth + 1) < 0) {
                free(order); return -1;
            }
        }
        free(order); return append(b, "}", 1);
    }
    }
    errno = EINVAL; return -1;
}
int tm_json_canonicalize(const struct tm_json_value *value,
                         unsigned char **output, size_t *length)
{
    struct buffer b = {0};
    if (value == NULL || output == NULL || length == NULL ||
        canonical(value, &b, 0) < 0) { free(b.data); return -1; }
    *output = b.data; *length = b.length; return 0;
}
