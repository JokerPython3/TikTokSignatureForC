#define _POSIX_C_SOURCE 200809L
#include "tiktoksignature/ladon.h"
#include "tiktoksignature/crypto_helpers.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static uint64_t ror64(uint64_t v, int n) {
    return (v >> n) | (v << (64 - n));
}

static int padding_size(int size) {
    int mod = size % 16;
    if (mod > 0) return size + (16 - mod);
    return size;
}

static uint8_t *pkcs7_pad_ladon(const uint8_t *data, int offset, int size, int block_size, size_t *out_len) {
    int pad_len = block_size - (size % block_size);
    *out_len = (size_t)(size + pad_len);
    uint8_t *p = (uint8_t *)malloc(*out_len);
    memcpy(p, data + offset, (size_t)size);
    for (int i = size; i < size + pad_len; i++) {
        p[i] = (uint8_t)pad_len;
    }
    return p;
}

static void encrypt_ladon_input(const uint8_t *hash_table, const uint8_t *block, int block_off, uint8_t out[16]) {
    uint64_t data0 = le64_read(block, block_off);
    uint64_t data1 = le64_read(block, block_off + 8);

    for (int i = 0; i < 0x22; i++) {
        uint64_t hash = le64_read(hash_table, i * 8);
        data1 = hash ^ (data0 + ror64(data1, 8));
        data0 = data1 ^ ror64(data0, 0x3D);
    }

    le64_write(out, 0, data0);
    le64_write(out, 1, data1);
}

static uint8_t *encrypt_ladon(const uint8_t *md5hex, size_t md5hex_len,
                               const uint8_t *data, size_t data_len,
                               int size, size_t *out_len) {
    uint8_t hash_table[272 + 16];
    memset(hash_table, 0, sizeof(hash_table));
    memcpy(hash_table, md5hex, md5hex_len);

    uint64_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[i] = le64_read(hash_table, i * 8);
    }

    uint64_t buffer_b0 = temp[0];
    uint64_t buffer_b8 = temp[1];

    uint64_t queue[2 + 0x22];
    queue[0] = temp[2];
    queue[1] = temp[3];
    int q_head = 0;

    for (int i = 0; i < 0x22; i++) {
        uint64_t x9 = buffer_b0;
        uint64_t x8 = buffer_b8;
        x8 = ror64(x8, 8);
        x8 = x8 + x9;
        x8 = x8 ^ (uint64_t)i;
        queue[q_head + 2 + i] = x8;
        x8 = x8 ^ ror64(x9, 61);
        le64_write(hash_table, i + 1, x8);
        buffer_b0 = x8;
        buffer_b8 = queue[q_head + i];
    }

    int new_size = padding_size(size);
    uint8_t *input = (uint8_t *)calloc((size_t)new_size, 1);
    memcpy(input, data, (data_len < (size_t)size) ? data_len : (size_t)size);

    size_t padded_len;
    uint8_t *padded = pkcs7_pad_ladon(input, 0, size, 16, &padded_len);
    free(input);

    uint8_t *output = (uint8_t *)malloc((size_t)new_size);
    for (int i = 0; i < new_size / 16; i++) {
        uint8_t block_out[16];
        encrypt_ladon_input(hash_table, padded, i * 16, block_out);
        memcpy(output + i * 16, block_out, 16);
    }
    free(padded);

    *out_len = (size_t)new_size;
    return output;
}

char *ladon_encrypt(int64_t khronos, int license_id, int aid,
                    const uint8_t *random_bytes) {
    uint8_t local_rand[4];
    if (random_bytes) {
        memcpy(local_rand, random_bytes, 4);
    } else {
        local_rand[0] = crypto_rand_byte();
        local_rand[1] = crypto_rand_byte();
        local_rand[2] = crypto_rand_byte();
        local_rand[3] = crypto_rand_byte();
    }

    char data_str[128];
    snprintf(data_str, sizeof(data_str), "%lld-%d-%d", (long long)khronos, license_id, aid);

    char aid_str[32];
    snprintf(aid_str, sizeof(aid_str), "%d", aid);
    size_t aid_len = strlen(aid_str);

    size_t keygen_len = 4 + aid_len;
    uint8_t *keygen = (uint8_t *)malloc(keygen_len);
    memcpy(keygen, local_rand, 4);
    memcpy(keygen + 4, aid_str, aid_len);

    char md5hex[33];
    md5_hex(keygen, keygen_len, md5hex);
    free(keygen);

    int size = (int)strlen(data_str);

    size_t enc_len;
    uint8_t *encrypted = encrypt_ladon((const uint8_t *)md5hex, 32,
                                        (const uint8_t *)data_str, strlen(data_str),
                                        size, &enc_len);

    size_t output_len = 4 + enc_len;
    uint8_t *output = (uint8_t *)malloc(output_len);
    memcpy(output, local_rand, 4);
    memcpy(output + 4, encrypted, enc_len);
    free(encrypted);

    /* Base64 encode */
    size_t b64_cap = 4 * ((output_len + 2) / 3) + 1;
    char *b64 = (char *)malloc(b64_cap);
    const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < output_len; i += 3) {
        uint32_t n = (uint32_t)output[i] << 16;
        if (i + 1 < output_len) n |= (uint32_t)output[i + 1] << 8;
        if (i + 2 < output_len) n |= (uint32_t)output[i + 2];
        b64[o++] = tbl[(n >> 18) & 0x3F];
        b64[o++] = tbl[(n >> 12) & 0x3F];
        b64[o++] = (i + 1 < output_len) ? tbl[(n >> 6) & 0x3F] : '=';
        b64[o++] = (i + 2 < output_len) ? tbl[n & 0x3F] : '=';
    }
    b64[o] = '\0';
    free(output);
    return b64;
}
