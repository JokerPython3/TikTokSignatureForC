#include "tiktoksignature/crypto_helpers.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int md5_evp(const void *data, size_t len, unsigned char *out, unsigned int *out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    int ok = EVP_DigestInit_ex(ctx, EVP_md5(), NULL) == 1
          && EVP_DigestUpdate(ctx, data, len) == 1
          && EVP_DigestFinal_ex(ctx, out, out_len) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static const char HEX_DIGITS[] = "0123456789abcdef";

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

void md5_digest(const uint8_t *data, size_t len, uint8_t out[MD5_DIGEST_SIZE]) {
    unsigned int out_len = 0;
    if (md5_evp(data, len, out, &out_len) == 0) {
        memset(out, 0, MD5_DIGEST_SIZE);
    }
}

void md5_hex(const uint8_t *data, size_t len, char out[33]) {
    uint8_t digest[MD5_DIGEST_SIZE];
    unsigned int out_len = 0;
    if (md5_evp(data, len, digest, &out_len) == 0) {
        memset(digest, 0, MD5_DIGEST_SIZE);
    }
    for (int i = 0; i < MD5_DIGEST_SIZE; i++) {
        out[i * 2]     = HEX_DIGITS[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX_DIGITS[digest[i] & 0x0F];
    }
    out[32] = '\0';
}

void md5_hex_str(const char *s, char out[33]) {
    md5_hex((const uint8_t *)s, strlen(s), out);
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_DIGITS[(bytes[i] >> 4) & 0x0F];
        out[i * 2 + 1] = HEX_DIGITS[bytes[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

void hex_byte_str(uint8_t b, char out[3]) {
    out[0] = HEX_DIGITS[(b >> 4) & 0x0F];
    out[1] = HEX_DIGITS[b & 0x0F];
    out[2] = '\0';
}

uint8_t *hex_decode_string(const char *s, size_t *out_len) {
    size_t len = strlen(s);
    *out_len = len / 2;
    uint8_t *out = (uint8_t *)malloc(*out_len);
    if (out == NULL) return NULL;
    for (size_t i = 0; i < len; i += 2) {
        out[i / 2] = (uint8_t)((hex_nibble(s[i]) << 4) | hex_nibble(s[i + 1]));
    }
    return out;
}

uint8_t *first_digest_bytes(const char *hex_digest, int n, size_t *out_len) {
    *out_len = (size_t)n;
    uint8_t *out = (uint8_t *)malloc((size_t)n);
    if (out == NULL) return NULL;
    for (int i = 0; i < n; i++) {
        int hi = hex_nibble(hex_digest[2 * i]);
        int lo = hex_nibble(hex_digest[2 * i + 1]);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return out;
}

uint8_t crypto_rand_byte(void) {
    uint8_t b;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &b, 1);
        close(fd);
    } else {
        b = (uint8_t)(rand() & 0xFF);
    }
    return b;
}

uint32_t crypto_rand_uint31(void) {
    uint8_t b[4];
    crypto_rand_bytes(b, 4);
    uint32_t v = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
               | ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
    return v & 0x7FFFFFFF;
}

void crypto_rand_bytes(uint8_t *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t total = 0;
        while (total < n) {
            ssize_t r = read(fd, buf + total, n - total);
            if (r <= 0) break;
            total += (size_t)r;
        }
        close(fd);
    } else {
        for (size_t i = 0; i < n; i++) {
            buf[i] = (uint8_t)(rand() & 0xFF);
        }
    }
}

uint64_t le64_read(const uint8_t *b, int off) {
    return (uint64_t)b[off]
         | ((uint64_t)b[off + 1] << 8)
         | ((uint64_t)b[off + 2] << 16)
         | ((uint64_t)b[off + 3] << 24)
         | ((uint64_t)b[off + 4] << 32)
         | ((uint64_t)b[off + 5] << 40)
         | ((uint64_t)b[off + 6] << 48)
         | ((uint64_t)b[off + 7] << 56);
}

void le64_write(uint8_t *dst, int index, uint64_t v) {
    int off = index * 8;
    dst[off]     = (uint8_t)(v);
    dst[off + 1] = (uint8_t)(v >> 8);
    dst[off + 2] = (uint8_t)(v >> 16);
    dst[off + 3] = (uint8_t)(v >> 24);
    dst[off + 4] = (uint8_t)(v >> 32);
    dst[off + 5] = (uint8_t)(v >> 40);
    dst[off + 6] = (uint8_t)(v >> 48);
    dst[off + 7] = (uint8_t)(v >> 56);
}
