#define _POSIX_C_SOURCE 200809L
#include "tiktoksignature/url_encode.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const char HEX_UPPER[] = "0123456789ABCDEF";

static int is_unreserved(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '_' || c == '.' || c == '-' || c == '~';
}

char *quote_plus(const char *s) {
    size_t slen = strlen(s);
    size_t cap = slen * 3 + 1;
    char *out = (char *)malloc(cap);
    size_t pos = 0;

    const unsigned char *us = (const unsigned char *)s;
    for (size_t i = 0; i < slen; i++) {
        unsigned char c = us[i];
        if (is_unreserved(c)) {
            out[pos++] = (char)c;
        } else if (c == ' ') {
            out[pos++] = '+';
        } else {
            out[pos++] = '%';
            out[pos++] = HEX_UPPER[(c >> 4) & 0x0F];
            out[pos++] = HEX_UPPER[c & 0x0F];
        }
    }
    out[pos] = '\0';
    return out;
}

char *unquote_plus(const char *s) {
    size_t slen = strlen(s);
    size_t cap = slen + 1;
    char *out = (char *)malloc(cap);
    size_t pos = 0;

    for (size_t i = 0; i < slen; i++) {
        if (s[i] == '+') {
            out[pos++] = ' ';
        } else if (s[i] == '%' && i + 2 < slen) {
            int hi = -1, lo = -1;
            if (s[i+1] >= '0' && s[i+1] <= '9') hi = s[i+1] - '0';
            else if (s[i+1] >= 'a' && s[i+1] <= 'f') hi = s[i+1] - 'a' + 10;
            else if (s[i+1] >= 'A' && s[i+1] <= 'F') hi = s[i+1] - 'A' + 10;
            if (s[i+2] >= '0' && s[i+2] <= '9') lo = s[i+2] - '0';
            else if (s[i+2] >= 'a' && s[i+2] <= 'f') lo = s[i+2] - 'a' + 10;
            else if (s[i+2] >= 'A' && s[i+2] <= 'F') lo = s[i+2] - 'A' + 10;
            if (hi >= 0 && lo >= 0) {
                out[pos++] = (char)((hi << 4) | lo);
                i += 2;
            } else {
                out[pos++] = s[i];
            }
        } else {
            out[pos++] = s[i];
        }
    }
    out[pos] = '\0';
    return out;
}

char *url_encode_params(const url_param_t *pairs, size_t count) {
    if (count == 0) {
        char *empty = (char *)malloc(1);
        empty[0] = '\0';
        return empty;
    }

    size_t cap = 256;
    char *out = (char *)malloc(cap);
    size_t pos = 0;

    for (size_t i = 0; i < count; i++) {
        char *ek = quote_plus(pairs[i].key);
        char *ev = quote_plus(pairs[i].value);

        size_t need = strlen(ek) + 1 + strlen(ev) + 1;
        while (pos + need >= cap) {
            cap *= 2;
            out = (char *)realloc(out, cap);
        }
        if (i > 0) out[pos++] = '&';
        strcpy(out + pos, ek);
        pos += strlen(ek);
        out[pos++] = '=';
        strcpy(out + pos, ev);
        pos += strlen(ev);

        free(ek);
        free(ev);
    }
    out[pos] = '\0';
    return out;
}

query_param_t *parse_query_params(const char *qs, size_t *out_count) {
    *out_count = 0;
    if (!qs || !qs[0]) return NULL;

    size_t cap = 16;
    query_param_t *params = (query_param_t *)malloc(cap * sizeof(query_param_t));

    char *work = strdup(qs);
    char *saveptr = NULL;
    char *token = strtok_r(work, "&", &saveptr);

    while (token) {
        char *eq = strchr(token, '=');
        if (!eq) { token = strtok_r(NULL, "&", &saveptr); continue; }

        *eq = '\0';
        char *name = token;
        char *value = eq + 1;
        if (!value[0]) { token = strtok_r(NULL, "&", &saveptr); continue; }

        char *dn = unquote_plus(name);
        char *dv = unquote_plus(value);

        /* skip if key already exists (keep first) */
        bool dup = false;
        for (size_t i = 0; i < *out_count; i++) {
            if (strcmp(params[i].key, dn) == 0) { dup = true; break; }
        }
        if (dup) {
            free(dn);
            free(dv);
            token = strtok_r(NULL, "&", &saveptr);
            continue;
        }

        if (*out_count >= cap) {
            cap *= 2;
            params = (query_param_t *)realloc(params, cap * sizeof(query_param_t));
        }
        params[*out_count].key = dn;
        params[*out_count].value = dv;
        (*out_count)++;

        token = strtok_r(NULL, "&", &saveptr);
    }

    free(work);
    return params;
}

void free_query_params(query_param_t *params, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free(params[i].key);
        free(params[i].value);
    }
    free(params);
}
