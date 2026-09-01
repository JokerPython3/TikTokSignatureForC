#ifndef TIKTOK_LADON_H
#define TIKTOK_LADON_H

#include <stdint.h>
#include <stddef.h>

char *ladon_encrypt(int64_t khronos, int license_id, int aid,
                    const uint8_t *random_bytes);

#endif
