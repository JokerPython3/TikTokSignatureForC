#include "tiktoksignature/simon.h"
#include <string.h>

static uint64_t rol64(uint64_t v, int n) {
    return (v << n) | (v >> (64 - n));
}

static uint64_t ror64(uint64_t v, int n) {
    return (v >> n) | (v << (64 - n));
}

static uint64_t get_bit(uint64_t val, int pos) {
    return (val >> pos) & 1ULL;
}

static const uint64_t Z = 0x3DC94C3A046D678BULL;

static void key_expansion(uint64_t key[72]) {
    for (int i = 4; i < 72; i++) {
        uint64_t tmp = ror64(key[i - 1], 3);
        tmp ^= key[i - 3];
        tmp ^= ror64(tmp, 1);
        key[i] = (~key[i - 4]) ^ tmp ^ get_bit(Z, (i - 4) % 62) ^ 3ULL;
    }
}

void simon_encrypt(const uint64_t pt[2], const uint64_t k[4], uint64_t ct[2]) {
    uint64_t key[72];
    memcpy(key, k, 4 * sizeof(uint64_t));
    key_expansion(key);

    uint64_t x = pt[0];
    uint64_t y = pt[1];
    for (int i = 0; i < 72; i++) {
        uint64_t tmp = y;
        uint64_t f = rol64(y, 1) & rol64(y, 8);
        y = x ^ f ^ rol64(y, 2) ^ key[i];
        x = tmp;
    }
    ct[0] = x;
    ct[1] = y;
}
