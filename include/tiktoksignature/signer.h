#ifndef TIKTOK_SIGNER_H
#define TIKTOK_SIGNER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "param.h"

/* tt_sign() error codes. On error the signature strings are NULL/empty and
 * must still be released with tt_signatures_free() (it is NULL-safe). */
enum {
    TT_SIGN_OK = 0,
    TT_SIGN_ERR_NULL_INPUT = 1,   /* req or opts is NULL */
    TT_SIGN_ERR_BAD_VERSION = 2,  /* unsupported gorgon version */
    TT_SIGN_ERR_ALLOC = 3         /* internal allocation failure */
};

typedef struct {
    int error; /* one of the tt_sign error codes (TT_SIGN_OK on success) */
    char *x_argus;
    char *x_ladon;
    char *x_gorgon;
    char *x_khronos;
    char *x_tt_request_ticket;
    char *x_ss_stub;
} tt_signatures_t;

typedef struct {
    const char *url;
    const tt_param_t *params;
    size_t params_count;
    const tt_param_t *data;
    size_t data_count;
    const tt_param_t *payload;
    size_t payload_count;
    const tt_param_t *cookie;
    size_t cookie_count;
    const char *raw_body;
} tt_sign_request_t;

typedef struct {
    int64_t timestamp;
    bool has_timestamp;
    int aid;
    int license_id;
    int platform;
    const char *sdk_version;
    int sdk_version_int;
    int version;
    const char *sec_device_id;
    bool has_gorgon_byte3;
    uint8_t gorgon_byte3;
    bool has_gorgon_byte7;
    uint8_t gorgon_byte7;
    bool has_argus_rand;
    int32_t argus_rand;
    bool has_ladon_random;
    uint8_t ladon_random[4];
} tt_sign_options_t;

tt_signatures_t tt_sign(const tt_sign_request_t *req, const tt_sign_options_t *opts);
void tt_signatures_free(tt_signatures_t *sig);

#endif
