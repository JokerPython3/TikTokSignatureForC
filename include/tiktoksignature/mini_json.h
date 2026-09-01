#ifndef TIKTOK_MINI_JSON_H
#define TIKTOK_MINI_JSON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_value json_value_t;

typedef struct {
    char *key;
    json_value_t *value;
} json_member_t;

struct json_value {
    json_type_t type;
    union {
        bool bool_val;
        double number_val;
        char *string_val;
        struct { json_value_t **items; size_t count; } array_val;
        struct { json_member_t *members; size_t count; } object_val;
    } u;
};

json_value_t *json_parse(const char *s);
void json_free(json_value_t *v);

const char *json_get_string(json_value_t *obj, const char *key);
int json_get_int(json_value_t *obj, const char *key, int default_val);
int64_t json_get_long(json_value_t *obj, const char *key, int64_t default_val);
double json_get_number(json_value_t *obj, const char *key, double default_val);
json_value_t *json_get(json_value_t *obj, const char *key);
size_t json_array_count(json_value_t *arr);
json_value_t *json_array_get(json_value_t *arr, size_t index);
const char *json_object_get_string(json_value_t *obj, const char *key);
double json_object_get_number(json_value_t *obj, const char *key);

#endif
