#ifndef TIKTOK_SM3_H
#define TIKTOK_SM3_H

#include <stdint.h>
#include <stddef.h>

#define SM3_DIGEST_SIZE 32

void sm3_hash(const uint8_t *msg, size_t len, uint8_t out[SM3_DIGEST_SIZE]);
void sm3_hash_str(const char *s, uint8_t out[SM3_DIGEST_SIZE]);

#endif
