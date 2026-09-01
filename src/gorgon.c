#define _POSIX_C_SOURCE 200809L
#include "tiktoksignature/gorgon.h"
#include "tiktoksignature/crypto_helpers.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static uint8_t nibble_swap(uint8_t b) {
    return (uint8_t)(((b >> 4) & 0x0F) | ((b & 0x0F) << 4));
}

static uint8_t bit_reverse(uint8_t b) {
    b = (uint8_t)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
    b = (uint8_t)(((b & 0xCC) >> 2) | ((b & 0x33) << 2));
    b = (uint8_t)(((b & 0xAA) >> 1) | ((b & 0x55) << 1));
    return b;
}

static void hex_of_unix(int64_t v, char out[9]) {
    snprintf(out, 9, "%08x", (unsigned)(v & 0xFFFFFFFF));
}

static void gorgon_result_init(gorgon_result_t *r) {
    r->req_ticket = NULL;
    r->khronos = NULL;
    r->gorgon_val = NULL;
}

void gorgon_result_free(gorgon_result_t *r) {
    free(r->req_ticket);
    free(r->khronos);
    free(r->gorgon_val);
    r->req_ticket = NULL;
    r->khronos = NULL;
    r->gorgon_val = NULL;
}

gorgon_result_t gorgon_v1(const char *params, const char *payload,
                           const char *cookie, int64_t unix_ts,
                           uint8_t b3, uint8_t b7) {
    gorgon_result_t r;
    gorgon_result_init(&r);

    uint8_t gorgon[20];
    memset(gorgon, 0, 20);
    int pos = 0;

    char url_md5[33];
    md5_hex_str(params ? params : "", url_md5);
    size_t url_bytes_len;
    uint8_t *url_bytes = first_digest_bytes(url_md5, 4, &url_bytes_len);
    memcpy(gorgon + pos, url_bytes, 4);
    free(url_bytes);
    pos += 4;

    if (payload && payload[0]) {
        char data_md5[33];
        md5_hex_str(payload, data_md5);
        size_t data_bytes_len;
        uint8_t *data_bytes = first_digest_bytes(data_md5, 4, &data_bytes_len);
        memcpy(gorgon + pos, data_bytes, 4);
        free(data_bytes);
    }
    pos += 4;

    if (cookie && cookie[0]) {
        char cookie_md5[33];
        md5_hex_str(cookie, cookie_md5);
        size_t cookie_bytes_len;
        uint8_t *cookie_bytes = first_digest_bytes(cookie_md5, 4, &cookie_bytes_len);
        memcpy(gorgon + pos, cookie_bytes, 4);
        free(cookie_bytes);
    }
    pos += 4;

    gorgon[pos]     = 0x01;
    gorgon[pos + 1] = 0x01;
    gorgon[pos + 2] = 0x02;
    gorgon[pos + 3] = 0x04;
    pos += 4;

    char khronos_str[9];
    hex_of_unix(unix_ts, khronos_str);
    size_t kh_bytes_len;
    uint8_t *kh_bytes = first_digest_bytes(khronos_str, 4, &kh_bytes_len);
    memcpy(gorgon + pos, kh_bytes, 4);
    free(kh_bytes);

    uint8_t ce07 = (uint8_t)(b7 & 0xF0);
    uint8_t ce03 = b3;
    uint8_t ce01 = 0x00;
    uint8_t ce06 = 0x00;

    char hex_buf[3];
    size_t sb_cap = 256;
    char *sb = (char *)malloc(sb_cap);
    size_t sb_pos = 0;

    const char *prefix = "8404";
    memcpy(sb + sb_pos, prefix, 4);
    sb_pos += 4;

    hex_byte_str(ce07, hex_buf);
    memcpy(sb + sb_pos, hex_buf, 2);
    sb_pos += 2;
    hex_byte_str(ce03, hex_buf);
    memcpy(sb + sb_pos, hex_buf, 2);
    sb_pos += 2;
    hex_byte_str(ce01, hex_buf);
    memcpy(sb + sb_pos, hex_buf, 2);
    sb_pos += 2;
    hex_byte_str(ce06, hex_buf);
    memcpy(sb + sb_pos, hex_buf, 2);
    sb_pos += 2;

    for (int i = 0; i < 20; i++) {
        hex_byte_str(gorgon[i], hex_buf);
        memcpy(sb + sb_pos, hex_buf, 2);
        sb_pos += 2;
    }
    sb[sb_pos] = '\0';

    r.gorgon_val = sb;

    char ticket_buf[64];
    snprintf(ticket_buf, sizeof(ticket_buf), "%lld", (long long)(unix_ts * 1000));
    r.req_ticket = strdup(ticket_buf);

    snprintf(ticket_buf, sizeof(ticket_buf), "%lld", (long long)unix_ts);
    r.khronos = strdup(ticket_buf);

    return r;
}

gorgon_result_t gorgon_v2(const char *params, const char *data,
                           const char *cookies, int64_t unix_ts) {
    gorgon_result_t r;
    gorgon_result_init(&r);

    uint8_t param_list[20];
    memset(param_list, 0, 20);
    int pos = 0;

    char params_md5[33];
    md5_hex_str(params ? params : "", params_md5);
    size_t p_bytes_len;
    uint8_t *p_bytes = first_digest_bytes(params_md5, 4, &p_bytes_len);
    memcpy(param_list + pos, p_bytes, 4);
    free(p_bytes);
    pos += 4;

    if (data && data[0]) {
        char data_md5[33];
        md5_hex_str(data, data_md5);
        size_t d_bytes_len;
        uint8_t *d_bytes = first_digest_bytes(data_md5, 4, &d_bytes_len);
        memcpy(param_list + pos, d_bytes, 4);
        free(d_bytes);
    }
    pos += 4;

    if (cookies && cookies[0]) {
        char cookie_md5[33];
        md5_hex_str(cookies, cookie_md5);
        size_t c_bytes_len;
        uint8_t *c_bytes = first_digest_bytes(cookie_md5, 4, &c_bytes_len);
        memcpy(param_list + pos, c_bytes, 4);
        free(c_bytes);
    }
    pos += 4;

    param_list[pos]     = 0x00;
    param_list[pos + 1] = 0x06;
    param_list[pos + 2] = 0x0B;
    param_list[pos + 3] = 0x1C;
    pos += 4;

    uint64_t h = (uint64_t)unix_ts & 0xFFFFFFFFULL;
    param_list[pos]     = (uint8_t)(h >> 24);
    param_list[pos + 1] = (uint8_t)(h >> 16);
    param_list[pos + 2] = (uint8_t)(h >> 8);
    param_list[pos + 3] = (uint8_t)(h);

    uint8_t key[20] = {
        0xDF, 0x77, 0xB9, 0x40, 0xB9, 0x9B, 0x84, 0x83,
        0xD1, 0xB9, 0xCB, 0xD1, 0xF7, 0xC2, 0xB9, 0x85,
        0xC3, 0xD0, 0xFB, 0xC3
    };

    int length = 0x14;
    uint8_t eor[20];
    for (int i = 0; i < length; i++) {
        eor[i] = (uint8_t)(param_list[i] ^ key[i]);
    }
    for (int i = 0; i < length; i++) {
        uint8_t c = nibble_swap(eor[i]);
        uint8_t d = eor[(i + 1) % length];
        uint8_t e = (uint8_t)(c ^ d);
        uint8_t f = bit_reverse(e);
        uint8_t hh = (uint8_t)((f & 0xFF) ^ 0xFF ^ length);
        eor[i] = hh;
    }

    size_t sb_cap = 256;
    char *sb = (char *)malloc(sb_cap);
    size_t sb_pos = 0;
    char hex_buf[3];

    for (int i = 0; i < 20; i++) {
        hex_byte_str(eor[i], hex_buf);
        memcpy(sb + sb_pos, hex_buf, 2);
        sb_pos += 2;
    }
    sb[sb_pos] = '\0';

    /* Prepend "840280416000" */
    size_t final_len = 12 + sb_pos + 1;
    char *final_str = (char *)malloc(final_len);
    memcpy(final_str, "840280416000", 12);
    memcpy(final_str + 12, sb, sb_pos + 1);
    free(sb);

    r.gorgon_val = final_str;

    char ticket_buf[64];
    snprintf(ticket_buf, sizeof(ticket_buf), "%lld", (long long)(unix_ts * 1000));
    r.req_ticket = strdup(ticket_buf);

    snprintf(ticket_buf, sizeof(ticket_buf), "%lld", (long long)unix_ts);
    r.khronos = strdup(ticket_buf);

    return r;
}

gorgon_result_t gorgon_v3(const char *params, const char *data,
                           const char *cookies, int64_t unix_ts) {
    gorgon_result_t r = gorgon_v2(params, data, cookies, unix_ts);
    if (r.gorgon_val) {
        size_t v2_prefix_len = strlen("840280416000");
        size_t suffix_len = strlen(r.gorgon_val + v2_prefix_len);
        size_t final_len = 12 + suffix_len + 1;
        char *final_str = (char *)malloc(final_len);
        memcpy(final_str, "0404b0d30000", 12);
        memcpy(final_str + 12, r.gorgon_val + v2_prefix_len, suffix_len + 1);
        free(r.gorgon_val);
        r.gorgon_val = final_str;
    }
    return r;
}
