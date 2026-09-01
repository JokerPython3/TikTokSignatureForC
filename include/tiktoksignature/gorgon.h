#ifndef TIKTOK_GORGON_H
#define TIKTOK_GORGON_H

#include <stdint.h>

typedef struct {
    char *req_ticket;
    char *khronos;
    char *gorgon_val;
} gorgon_result_t;

gorgon_result_t gorgon_v1(const char *params, const char *payload,
                           const char *cookie, int64_t unix_ts,
                           uint8_t b3, uint8_t b7);
gorgon_result_t gorgon_v2(const char *params, const char *data,
                           const char *cookies, int64_t unix_ts);
gorgon_result_t gorgon_v3(const char *params, const char *data,
                           const char *cookies, int64_t unix_ts);

void gorgon_result_free(gorgon_result_t *r);

#endif
