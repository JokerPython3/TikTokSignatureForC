#ifndef TIKTOK_CRYPTO_HELPERS_H
#define TIKTOK_CRYPTO_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MD5_DIGEST_SIZE 16

void md5_digest(const uint8_t *data, size_t len, uint8_t out[MD5_DIGEST_SIZE]);
void md5_hex(const uint8_t *data, size_t len, char out[33]);
void md5_hex_str(const char *s, char out[33]);

void bytes_to_hex(const uint8_t *bytes, size_t len, char *out);
void hex_byte_str(uint8_t b, char out[3]);
uint8_t *hex_decode_string(const char *s, size_t *out_len);
uint8_t *first_digest_bytes(const char *hex_digest, int n, size_t *out_len);

uint8_t crypto_rand_byte(void);
uint32_t crypto_rand_uint31(void);
void crypto_rand_bytes(uint8_t *buf, size_t n);

uint64_t le64_read(const uint8_t *b, int off);
void le64_write(uint8_t *dst, int index, uint64_t v);

#endif
