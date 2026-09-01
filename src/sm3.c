#include "tiktoksignature/sm3.h"
#include <string.h>
#include <stdlib.h>

static const uint32_t IV[8] = {
    0x7380166Fu, 0x4914B2B9u, 0x172442D7u, 0xDA8A0600u,
    0xA96F30BCu, 0x163138AAu, 0xE38DEE4Du, 0xB0FB0E4Eu
};

static uint32_t TJ[64];

static void tj_init(void) {
    static int done = 0;
    if (done) return;
    for (int i = 0; i < 16; i++) TJ[i] = 0x79CC4519u;
    for (int i = 16; i < 64; i++) TJ[i] = 0x7A879D8Au;
    done = 1;
}

static uint32_t rotl32(uint32_t a, int k) {
    k %= 32;
    if (k == 0) return a;
    return (a << k) | (a >> (32 - k));
}

static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

static uint32_t p0(uint32_t x) {
    return x ^ rotl32(x, 9) ^ rotl32(x, 17);
}

static uint32_t p1(uint32_t x) {
    return x ^ rotl32(x, 15) ^ rotl32(x, 23);
}

static uint32_t read_be32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  | (uint32_t)b[3];
}

static void write_be32(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static void cf(uint32_t v[8], const uint8_t block[64]) {
    uint32_t w[68];
    uint32_t w1[64];

    for (int i = 0; i < 16; i++) {
        w[i] = read_be32(block + i * 4);
    }
    for (int j = 16; j < 68; j++) {
        w[j] = p1(w[j-16] ^ w[j-9] ^ rotl32(w[j-3], 15))
              ^ rotl32(w[j-13], 7) ^ w[j-6];
    }
    for (int j = 0; j < 64; j++) {
        w1[j] = w[j] ^ w[j+4];
    }

    uint32_t a = v[0], b = v[1], c = v[2], d = v[3];
    uint32_t e = v[4], f = v[5], g = v[6], h = v[7];

    for (int j = 0; j < 64; j++) {
        uint32_t ss1 = rotl32(rotl32(a, 12) + e + rotl32(TJ[j], j), 7);
        uint32_t ss2 = ss1 ^ rotl32(a, 12);
        uint32_t tt1 = ff(a, b, c, j) + d + ss2 + w1[j];
        uint32_t tt2 = gg(e, f, g, j) + h + ss1 + w[j];
        d = c;
        c = rotl32(b, 9);
        b = a;
        a = tt1;
        h = g;
        g = rotl32(f, 19);
        f = e;
        e = p0(tt2);
    }

    v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
    v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
}

void sm3_hash(const uint8_t *msg, size_t len, uint8_t out[SM3_DIGEST_SIZE]) {
    tj_init();

    size_t total = len + 1 + 16;
    int reserve = (int)(len % 64) + 1;
    int range_end = 56;
    if (reserve > range_end) range_end += 64;
    int pad_start = (int)len + 1;
    total = (size_t)(pad_start + (range_end - reserve));

    uint8_t *m = (uint8_t *)calloc(total + 64, 1);
    if (m == NULL) return;
    if (msg == NULL && len > 0) { free(m); return; }
    memcpy(m, msg, len);
    m[len] = 0x80;

    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 7; i >= 0; i--) {
        m[total++] = (uint8_t)(bit_len >> (i * 8));
    }

    uint32_t v[8];
    memcpy(v, IV, sizeof(IV));

    size_t blocks = total / 64;
    for (size_t i = 0; i < blocks; i++) {
        cf(v, m + i * 64);
    }

    for (int i = 0; i < 8; i++) {
        write_be32(out + i * 4, v[i]);
    }

    free(m);
}

void sm3_hash_str(const char *s, uint8_t out[SM3_DIGEST_SIZE]) {
    sm3_hash((const uint8_t *)s, strlen(s), out);
}
