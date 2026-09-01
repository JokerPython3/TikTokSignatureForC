#define _POSIX_C_SOURCE 200809L
#include "tiktoksignature/mini_json.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

typedef struct {
    const char *s;
    size_t pos;
} json_parser_t;

static void skip_ws(json_parser_t *p) {
    while (p->s[p->pos] && isspace((unsigned char)p->s[p->pos])) p->pos++;
}

static json_value_t *parse_value(json_parser_t *p);
static char *parse_string_raw(json_parser_t *p);

static json_value_t *new_value(json_type_t t) {
    json_value_t *v = (json_value_t *)calloc(1, sizeof(json_value_t));
    v->type = t;
    return v;
}

static void expect_str(json_parser_t *p, const char *lit) {
    size_t len = strlen(lit);
    if (strncmp(p->s + p->pos, lit, len) != 0) {
        fprintf(stderr, "JSON parse error: expected '%s' at position %zu\n", lit, p->pos);
        exit(1);
    }
    p->pos += len;
}

static json_value_t *parse_object(json_parser_t *p) {
    json_value_t *v = new_value(JSON_OBJECT);
    p->pos++; /* { */
    skip_ws(p);
    if (p->s[p->pos] == '}') { p->pos++; return v; }

    size_t cap = 8;
    v->u.object_val.members = (json_member_t *)malloc(cap * sizeof(json_member_t));
    v->u.object_val.count = 0;

    while (1) {
        skip_ws(p);
        if (p->s[p->pos] != '"') { fprintf(stderr, "expected key\n"); exit(1); }
        char *key = parse_string_raw(p);
        skip_ws(p);
        if (p->s[p->pos] != ':') { fprintf(stderr, "expected :\n"); exit(1); }
        p->pos++;
        json_value_t *val = parse_value(p);

        if (v->u.object_val.count >= cap) {
            cap *= 2;
            v->u.object_val.members = (json_member_t *)realloc(
                v->u.object_val.members, cap * sizeof(json_member_t));
        }
        v->u.object_val.members[v->u.object_val.count].key = key;
        v->u.object_val.members[v->u.object_val.count].value = val;
        v->u.object_val.count++;

        skip_ws(p);
        if (p->s[p->pos] == ',') { p->pos++; continue; }
        if (p->s[p->pos] == '}') { p->pos++; return v; }
        fprintf(stderr, "expected , or }\n"); exit(1);
    }
}

static json_value_t *parse_array(json_parser_t *p) {
    json_value_t *v = new_value(JSON_ARRAY);
    p->pos++; /* [ */
    skip_ws(p);
    if (p->s[p->pos] == ']') { p->pos++; return v; }

    size_t cap = 8;
    v->u.array_val.items = (json_value_t **)malloc(cap * sizeof(json_value_t *));
    v->u.array_val.count = 0;

    while (1) {
        json_value_t *item = parse_value(p);
        if (v->u.array_val.count >= cap) {
            cap *= 2;
            v->u.array_val.items = (json_value_t **)realloc(
                v->u.array_val.items, cap * sizeof(json_value_t *));
        }
        v->u.array_val.items[v->u.array_val.count++] = item;

        skip_ws(p);
        if (p->s[p->pos] == ',') { p->pos++; continue; }
        if (p->s[p->pos] == ']') { p->pos++; return v; }
        fprintf(stderr, "expected , or ]\n"); exit(1);
    }
}

static char *parse_string_raw(json_parser_t *p) {
    if (p->s[p->pos] != '"') { fprintf(stderr, "expected \"\n"); exit(1); }
    p->pos++;
    size_t cap = 64;
    size_t len = 0;
    char *buf = (char *)malloc(cap);

    while (p->s[p->pos]) {
        char c = p->s[p->pos];
        if (c == '"') { p->pos++; buf[len] = '\0'; return buf; }
        if (c == '\\') {
            p->pos++;
            char e = p->s[p->pos];
            char out;
            switch (e) {
                case '"': out = '"'; break;
                case '\\': out = '\\'; break;
                case '/': out = '/'; break;
                case 'b': out = '\b'; break;
                case 'f': out = '\f'; break;
                case 'n': out = '\n'; break;
                case 'r': out = '\r'; break;
                case 't': out = '\t'; break;
                case 'u': {
                    char hex[5] = {p->s[p->pos+1], p->s[p->pos+2], p->s[p->pos+3], p->s[p->pos+4], 0};
                    int cp = (int)strtol(hex, NULL, 16);
                    if (len + 4 >= cap) { cap *= 2; buf = realloc(buf, cap); }
                    if (cp < 0x80) {
                        buf[len++] = (char)cp;
                    } else if (cp < 0x800) {
                        buf[len++] = (char)(0xC0 | (cp >> 6));
                        buf[len++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        buf[len++] = (char)(0xE0 | (cp >> 12));
                        buf[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        buf[len++] = (char)(0x80 | (cp & 0x3F));
                    }
                    p->pos += 5;
                    goto next;
                }
                default: fprintf(stderr, "bad escape %c\n", e); exit(1);
            }
            if (len + 1 >= cap) { cap *= 2; buf = realloc(buf, cap); }
            buf[len++] = out;
            p->pos++;
        } else {
            if (len + 1 >= cap) { cap *= 2; buf = realloc(buf, cap); }
            buf[len++] = c;
            p->pos++;
        }
        next:;
    }
    fprintf(stderr, "unterminated string\n"); exit(1);
}

static json_value_t *parse_number(json_parser_t *p) {
    json_value_t *v = new_value(JSON_NUMBER);
    size_t start = p->pos;
    while (p->s[p->pos] && strchr("+-0123456789.eE", p->s[p->pos])) p->pos++;
    char num[128];
    size_t nlen = p->pos - start;
    if (nlen >= sizeof(num)) nlen = sizeof(num) - 1;
    memcpy(num, p->s + start, nlen);
    num[nlen] = '\0';
    v->u.number_val = atof(num);
    return v;
}

static json_value_t *parse_value(json_parser_t *p) {
    skip_ws(p);
    char c = p->s[p->pos];
    switch (c) {
        case '{': return parse_object(p);
        case '[': return parse_array(p);
        case '"': {
            json_value_t *v = new_value(JSON_STRING);
            v->u.string_val = parse_string_raw(p);
            return v;
        }
        case 't': expect_str(p, "true"); {
            json_value_t *v = new_value(JSON_BOOL);
            v->u.bool_val = true;
            return v;
        }
        case 'f': expect_str(p, "false"); {
            json_value_t *v = new_value(JSON_BOOL);
            v->u.bool_val = false;
            return v;
        }
        case 'n': expect_str(p, "null"); return new_value(JSON_NULL);
        default: return parse_number(p);
    }
}

json_value_t *json_parse(const char *s) {
    json_parser_t p = {s, 0};
    json_value_t *v = parse_value(&p);
    skip_ws(&p);
    return v;
}

void json_free(json_value_t *v) {
    if (!v) return;
    switch (v->type) {
        case JSON_STRING:
            free(v->u.string_val);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < v->u.array_val.count; i++) {
                json_free(v->u.array_val.items[i]);
            }
            free(v->u.array_val.items);
            break;
        case JSON_OBJECT:
            for (size_t i = 0; i < v->u.object_val.count; i++) {
                free(v->u.object_val.members[i].key);
                json_free(v->u.object_val.members[i].value);
            }
            free(v->u.object_val.members);
            break;
        default:
            break;
    }
    free(v);
}

json_value_t *json_get(json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    for (size_t i = 0; i < obj->u.object_val.count; i++) {
        if (strcmp(obj->u.object_val.members[i].key, key) == 0) {
            return obj->u.object_val.members[i].value;
        }
    }
    return NULL;
}

const char *json_get_string(json_value_t *obj, const char *key) {
    json_value_t *v = json_get(obj, key);
    if (!v || v->type != JSON_STRING) return NULL;
    return v->u.string_val;
}

int json_get_int(json_value_t *obj, const char *key, int default_val) {
    json_value_t *v = json_get(obj, key);
    if (!v) return default_val;
    if (v->type == JSON_NUMBER) return (int)v->u.number_val;
    if (v->type == JSON_STRING) return atoi(v->u.string_val);
    return default_val;
}

int64_t json_get_long(json_value_t *obj, const char *key, int64_t default_val) {
    json_value_t *v = json_get(obj, key);
    if (!v) return default_val;
    if (v->type == JSON_NUMBER) return (int64_t)v->u.number_val;
    if (v->type == JSON_STRING) return (int64_t)strtoll(v->u.string_val, NULL, 10);
    return default_val;
}

double json_get_number(json_value_t *obj, const char *key, double default_val) {
    json_value_t *v = json_get(obj, key);
    if (!v) return default_val;
    if (v->type == JSON_NUMBER) return v->u.number_val;
    return default_val;
}

size_t json_array_count(json_value_t *arr) {
    if (!arr || arr->type != JSON_ARRAY) return 0;
    return arr->u.array_val.count;
}

json_value_t *json_array_get(json_value_t *arr, size_t index) {
    if (!arr || arr->type != JSON_ARRAY || index >= arr->u.array_val.count) return NULL;
    return arr->u.array_val.items[index];
}

const char *json_object_get_string(json_value_t *obj, const char *key) {
    return json_get_string(obj, key);
}

double json_object_get_number(json_value_t *obj, const char *key) {
    return json_get_number(obj, key, 0.0);
}
