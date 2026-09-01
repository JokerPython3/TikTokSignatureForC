#ifndef TIKTOK_SIMON_H
#define TIKTOK_SIMON_H

#include <stdint.h>

void simon_encrypt(const uint64_t pt[2], const uint64_t k[4], uint64_t ct[2]);

#endif
