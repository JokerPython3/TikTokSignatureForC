#define _POSIX_C_SOURCE 200809L
#include "tiktoksignature/signer.h"
#include "tiktoksignature/argus.h"
#include "tiktoksignature/ladon.h"
#include "tiktoksignature/gorgon.h"
#include "tiktoksignature/crypto_helpers.h"
#include "tiktoksignature/url_encode.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static url_param_t *to_url_params(const tt_param_t *params, size_t count) {
    url_param_t *up = (url_param_t *)malloc(count * sizeof(url_param_t));
    for (size_t i = 0; i < count; i++) {
        up[i].key = params[i].key;
        up[i].value = params[i].value;
    }
    return up;
}

static tt_param_t *params_from_url(const char *url, size_t *out_count) {
    *out_count = 0;
    const char *qmark = strchr(url, '?');
    const char *query = qmark ? qmark + 1 : "";
    if (!query[0]) return NULL;

    tt_param_t *params = NULL;
    size_t cap = 0;
    size_t count = 0;

    char *work = strdup(query);
    char *saveptr = NULL;
    char *token = strtok_r(work, "&", &saveptr);

    while (token) {
        char *eq = strchr(token, '=');
        char *k, *v;
        if (eq) {
            *eq = '\0';
            k = token;
            v = eq + 1;
        } else {
            k = token;
            v = "";
        }

        /* check if key already exists - update it */
        bool found = false;
        for (size_t i = 0; i < count; i++) {
            if (strcmp(params[i].key, k) == 0) {
                free(params[i].value);
                params[i].value = strdup(v);
                found = true;
                break;
            }
        }
        if (!found) {
            if (count >= cap) {
                cap = cap ? cap * 2 : 16;
                params = realloc(params, cap * sizeof(tt_param_t));
            }
            params[count].key = strdup(k);
            params[count].value = strdup(v);
            count++;
        }

        token = strtok_r(NULL, "&", &saveptr);
    }
    free(work);
    *out_count = count;
    return params;
}

tt_signatures_t tt_sign(const tt_sign_request_t *req, const tt_sign_options_t *opts) {
    tt_signatures_t sig;
    memset(&sig, 0, sizeof(sig));
    if (!req || !opts) {
        sig.error = TT_SIGN_ERR_NULL_INPUT;
        return sig;
    }

    int aid = opts->aid == 0 ? 1233 : opts->aid;
    int license_id = opts->license_id == 0 ? 1611921764 : opts->license_id;
    const char *sdk_version = (!opts->sdk_version || !opts->sdk_version[0])
                              ? "v05.00.06-ov-android" : opts->sdk_version;
    int sdk_version_int = opts->sdk_version_int == 0 ? 167775296 : opts->sdk_version_int;

    int64_t unix_ts;
    if (opts->has_timestamp) {
        unix_ts = opts->timestamp;
    } else {
        unix_ts = (int64_t)time(NULL);
    }

    /* Merge data/payload */
    const tt_param_t *data = req->data;
    size_t data_count = req->data_count;
    const tt_param_t *payload = req->payload;
    size_t payload_count = req->payload_count;

    if ((data_count == 0) && payload_count > 0) {
        data = payload;
        data_count = payload_count;
    } else if ((payload_count == 0) && data_count > 0) {
        payload = data;
        payload_count = data_count;
    }

    /* Handle params from URL if not provided */
    const tt_param_t *params = req->params;
    size_t params_count = req->params_count;
    tt_param_t *url_params = NULL;
    size_t url_params_count = 0;

    if (!params && req->url && req->url[0]) {
        url_params = params_from_url(req->url, &url_params_count);
        params = url_params;
        params_count = url_params_count;
    }
    if (!params) {
        static const tt_param_t empty = {NULL, NULL};
        params = &empty;
        params_count = 0;
    }

    const tt_param_t *cookie = req->cookie;
    size_t cookie_count = req->cookie_count;
    if (!cookie) {
        cookie_count = 0;
    }

    /* URL encode all param lists */
    url_param_t *up_params = to_url_params(params, params_count);
    char *params_str = url_encode_params(up_params, params_count);
    free(up_params);

    url_param_t *up_payload = to_url_params(payload, payload_count);
    char *payload_str = url_encode_params(up_payload, payload_count);
    free(up_payload);

    url_param_t *up_cookie = to_url_params(cookie, cookie_count);
    char *cookie_str = url_encode_params(up_cookie, cookie_count);
    free(up_cookie);

    url_param_t *up_data = to_url_params(data, data_count);
    char *data_str = url_encode_params(up_data, data_count);
    free(up_data);

    if (req->raw_body && req->raw_body[0]) {
        free(data_str);
        data_str = strdup(req->raw_body);
    }

    /* MD5 stub */
    char stub[33];
    md5_hex_str(data_str, stub);

    /* Stub uppercase for X-SS-Stub */
    char stub_upper[33];
    for (int i = 0; i < 32; i++) {
        stub_upper[i] = (stub[i] >= 'a' && stub[i] <= 'f')
                        ? (char)(stub[i] - 32) : stub[i];
    }
    stub_upper[32] = '\0';

    char *req_ticket = NULL;
    char *khronos = NULL;
    char *gorgon_val = NULL;

    int version = opts->version;
    uint8_t b3, b7;

    switch (version) {
        case 8404: {
            b3 = opts->has_gorgon_byte3 ? opts->gorgon_byte3 : crypto_rand_byte();
            b7 = opts->has_gorgon_byte7 ? opts->gorgon_byte7 : crypto_rand_byte();
            gorgon_result_t gr = gorgon_v1(params_str, payload_str, cookie_str, unix_ts, b3, b7);
            req_ticket = gr.req_ticket;
            khronos = gr.khronos;
            gorgon_val = gr.gorgon_val;
            break;
        }
        case 8402: {
            gorgon_result_t gr = gorgon_v2(params_str, payload_str, cookie_str, unix_ts);
            req_ticket = gr.req_ticket;
            khronos = gr.khronos;
            gorgon_val = gr.gorgon_val;
            break;
        }
        case 4404:
        case 0: {
            gorgon_result_t gr = gorgon_v3(params_str, payload_str, cookie_str, unix_ts);
            req_ticket = gr.req_ticket;
            khronos = gr.khronos;
            gorgon_val = gr.gorgon_val;
            break;
        }
        default:
            fprintf(stderr, "unsupported gorgon version %d\n", version);
            sig.error = TT_SIGN_ERR_BAD_VERSION;
            free(params_str);
            free(payload_str);
            free(cookie_str);
            free(data_str);
            return sig;
    }

    const char *sec_device_id = opts->sec_device_id;
    if (!sec_device_id || !sec_device_id[0]) {
        static char default_sec_dev[32] = {0};
        static int initialized = 0;
        if (!initialized) {
            const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            strcpy(default_sec_dev, "AadCFwpTyztA5j9L");
            uint8_t buf[9];
            crypto_rand_bytes(buf, 9);
            size_t len = strlen(default_sec_dev);
            for (int i = 0; i < 9; i++) {
                default_sec_dev[len + i] = chars[buf[i] % 62];
            }
            default_sec_dev[len + 9] = '\0';
            initialized = 1;
        }
        sec_device_id = default_sec_dev;
    }

    int32_t argus_rand = opts->has_argus_rand ? opts->argus_rand : -1;

    sig.x_argus = argus_get_sign(params_str, stub, unix_ts, aid, license_id,
                                  opts->platform, sec_device_id, sdk_version,
                                  sdk_version_int, argus_rand);

    sig.x_ladon = ladon_encrypt(unix_ts, license_id, aid,
                                 opts->has_ladon_random ? opts->ladon_random : NULL);

    sig.x_gorgon = gorgon_val;
    sig.x_khronos = khronos;
    sig.x_tt_request_ticket = req_ticket;
    sig.x_ss_stub = strdup(stub_upper);

    if (!sig.x_argus || !sig.x_ladon || !sig.x_gorgon ||
        !sig.x_khronos || !sig.x_tt_request_ticket || !sig.x_ss_stub) {
        sig.error = TT_SIGN_ERR_ALLOC;
    }

    free(params_str);
    free(payload_str);
    free(cookie_str);
    free(data_str);
    if (url_params) {
        for (size_t i = 0; i < url_params_count; i++) {
            free(url_params[i].key);
            free(url_params[i].value);
        }
        free(url_params);
    }

    return sig;
}

void tt_signatures_free(tt_signatures_t *sig) {
    if (!sig) return;
    free(sig->x_argus);
    free(sig->x_ladon);
    free(sig->x_gorgon);
    free(sig->x_khronos);
    free(sig->x_tt_request_ticket);
    free(sig->x_ss_stub);
    memset(sig, 0, sizeof(*sig));
}
