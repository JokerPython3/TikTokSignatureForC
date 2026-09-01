#ifndef TIKTOK_URL_ENCODE_H
#define TIKTOK_URL_ENCODE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char *key;
    char *value;
} url_param_t;

char *url_encode_params(const url_param_t *pairs, size_t count);
char *quote_plus(const char *s);
char *unquote_plus(const char *s);

typedef struct {
    char *key;
    char *value;
} query_param_t;

query_param_t *parse_query_params(const char *qs, size_t *out_count);
void free_query_params(query_param_t *params, size_t count);

#endif
