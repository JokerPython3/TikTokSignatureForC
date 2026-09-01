#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include "tiktoksignature/signer.h"
#include "tiktoksignature/crypto_helpers.h"
#include "tiktoksignature/url_encode.h"
#include "tiktoksignature/mini_json.h"

#define TARGET_URL "https://api16-normal-c-alisg.tiktokv.com/passport/email/send_code/"

static int debug_enabled(void) {
    const char *d = getenv("DEBUG");
    if (!d) return 0;
    return (strcmp(d, "1") == 0 || strcmp(d, "true") == 0 ||
            strcmp(d, "yes") == 0 || strcmp(d, "on") == 0);
}

static char *xor_encode(const char *s) {
    size_t len = strlen(s);
    char *out = (char *)malloc(len * 2 + 1);
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        pos += snprintf(out + pos, 3, "%x", (unsigned char)(s[i] ^ 5));
    }
    out[pos] = '\0';
    return out;
}

static void add_param(tt_param_t **list, size_t *count, size_t *cap,
                      const char *k, const char *v) {
    if (*count >= *cap) {
        *cap = *cap ? *cap * 2 : 32;
        *list = (tt_param_t *)realloc(*list, *cap * sizeof(tt_param_t));
    }
    (*list)[*count].key = strdup(k);
    (*list)[*count].value = strdup(v);
    (*count)++;
}

static char *hex_uuid4(void) {
    uint8_t b[16];
    crypto_rand_bytes(b, 16);
    b[6] = (uint8_t)((b[6] & 0x0f) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3f) | 0x80);
    char *h = (char *)malloc(37);
    for (int i = 0; i < 16; i++) {
        snprintf(h + i * 2, 3, "%02x", b[i]);
    }
    h[32] = '\0';
    char *uuid = (char *)malloc(37);
    snprintf(uuid, 37, "%.8s-%.4s-%.4s-%.4s-%.12s",
             h, h + 8, h + 12, h + 16, h + 20);
    free(h);
    return uuid;
}

struct response {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct response *r = (struct response *)userp;
    r->data = (char *)realloc(r->data, r->size + realsize + 1);
    memcpy(r->data + r->size, contents, realsize);
    r->size += realsize;
    r->data[r->size] = '\0';
    return realsize;
}

static int64_t rand_int64_range(int64_t min, int64_t max) {
    uint64_t range = (uint64_t)(max - min) + 1;
    uint8_t b[8];
    crypto_rand_bytes(b, 8);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return min + (int64_t)(v % range);
}

int main(void) {
    printf("[1] Building request\n");

    int64_t now_unix = (int64_t)time(NULL);
    int64_t now_milli = now_unix * 1000;

    tt_param_t *params = NULL;
    size_t params_count = 0;
    size_t params_cap = 0;

    add_param(&params, &params_count, &params_cap, "passport-sdk-version", "6041890");
    add_param(&params, &params_count, &params_cap, "device_platform", "android");
    add_param(&params, &params_count, &params_cap, "os", "android");
    add_param(&params, &params_count, &params_cap, "ssmix", "a");

    char rticket[64];
    snprintf(rticket, sizeof(rticket), "%lld", (long long)now_milli);
    add_param(&params, &params_count, &params_cap, "_rticket", rticket);

    char *cdid = hex_uuid4();
    add_param(&params, &params_count, &params_cap, "cdid", cdid);
    free(cdid);

    add_param(&params, &params_count, &params_cap, "channel", "googleplay");
    add_param(&params, &params_count, &params_cap, "aid", "1233");
    add_param(&params, &params_count, &params_cap, "app_name", "musical_ly");
    add_param(&params, &params_count, &params_cap, "version_code", "410903");
    add_param(&params, &params_count, &params_cap, "version_name", "41.9.3");
    add_param(&params, &params_count, &params_cap, "manifest_version_code", "2024109030");
    add_param(&params, &params_count, &params_cap, "update_version_code", "2024109030");
    add_param(&params, &params_count, &params_cap, "ab_version", "41.9.3");
    add_param(&params, &params_count, &params_cap, "resolution", "1920*985");
    add_param(&params, &params_count, &params_cap, "dpi", "180");
    add_param(&params, &params_count, &params_cap, "device_type", "WayDroid x86_64 Device");
    add_param(&params, &params_count, &params_cap, "device_brand", "waydroid");
    add_param(&params, &params_count, &params_cap, "language", "en");
    add_param(&params, &params_count, &params_cap, "os_api", "33");
    add_param(&params, &params_count, &params_cap, "os_version", "13");
    add_param(&params, &params_count, &params_cap, "ac", "mobile");
    add_param(&params, &params_count, &params_cap, "is_pad", "1");
    add_param(&params, &params_count, &params_cap, "app_type", "normal");
    add_param(&params, &params_count, &params_cap, "sys_region", "US");
    add_param(&params, &params_count, &params_cap, "last_install_time", "1788041680");
    add_param(&params, &params_count, &params_cap, "timezone_name", "GMT");
    add_param(&params, &params_count, &params_cap, "app_language", "en");
    add_param(&params, &params_count, &params_cap, "timezone_offset", "0");
    add_param(&params, &params_count, &params_cap, "host_abi", "arm64-v8a");
    add_param(&params, &params_count, &params_cap, "locale", "en");
    add_param(&params, &params_count, &params_cap, "ac2", "unknown");
    add_param(&params, &params_count, &params_cap, "uoo", "1");
    add_param(&params, &params_count, &params_cap, "op_region", "US");
    add_param(&params, &params_count, &params_cap, "build_number", "41.9.3");
    add_param(&params, &params_count, &params_cap, "region", "US");

    char ts_str[64];
    snprintf(ts_str, sizeof(ts_str), "%lld", (long long)now_unix);
    add_param(&params, &params_count, &params_cap, "ts", ts_str);

    char iid_str[32];
    snprintf(iid_str, sizeof(iid_str), "%lld",
             (long long)rand_int64_range(7400000000000000000LL,
                                         7499999999999999999LL));
    add_param(&params, &params_count, &params_cap, "iid", iid_str);

    char device_id_str[32];
    snprintf(device_id_str, sizeof(device_id_str), "%lld",
             (long long)rand_int64_range(7400000000000000000LL,
                                         7499999999999999999LL));
    add_param(&params, &params_count, &params_cap, "device_id", device_id_str);

    uint8_t rand8[8];
    crypto_rand_bytes(rand8, 8);
    char openudid[17];
    for (int i = 0; i < 8; i++) snprintf(openudid + i * 2, 3, "%02x", rand8[i]);
    openudid[16] = '\0';
    add_param(&params, &params_count, &params_cap, "openudid", openudid);

    add_param(&params, &params_count, &params_cap, "support_webview", "1");
    add_param(&params, &params_count, &params_cap, "reg_store_region", "ca");
    add_param(&params, &params_count, &params_cap, "user_selected_region", "0");
    add_param(&params, &params_count, &params_cap, "okhttp_version", "4.2.243.16-tiktok-fix");
    add_param(&params, &params_count, &params_cap, "use_store_region_cookie", "1");

    printf("Enter email to send code -> ");
    char email[256];
    if (!fgets(email, sizeof(email), stdin)) {
        fprintf(stderr, "Failed to read email\n");
        return 1;
    }
    email[strcspn(email, "\n")] = '\0';

    tt_param_t *data = NULL;
    size_t data_count = 0;
    size_t data_cap = 0;

    add_param(&data, &data_count, &data_cap, "account_sdk_source", "app");
    add_param(&data, &data_count, &data_cap, "rule_strategies", "2");
    add_param(&data, &data_count, &data_cap, "mix_mode", "1");
    add_param(&data, &data_count, &data_cap, "multi_login", "1");
    add_param(&data, &data_count, &data_cap, "type", "3736");

    char *xored = xor_encode(email);
    add_param(&data, &data_count, &data_cap, "email", xored);
    free(xored);

    add_param(&data, &data_count, &data_cap, "email_theme", "2");
    add_param(&data, &data_count, &data_cap, "use_passport_ticket", "1");
    add_param(&data, &data_count, &data_cap, "scene", "3");

    tt_sign_request_t req;
    memset(&req, 0, sizeof(req));
    req.params = params;
    req.params_count = params_count;
    req.data = data;
    req.data_count = data_count;

    tt_sign_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.has_timestamp = true;
    opts.timestamp = now_unix;
    opts.aid = 1233;
    opts.version = 8404;

    tt_signatures_t sig = tt_sign(&req, &opts);

    if (sig.error != TT_SIGN_OK) {
        fprintf(stderr, "tt_sign failed: error code %d (0=%s, 1=NULL input, "
                "2=bad gorgon version, 3=allocation failure)\n", sig.error,
                sig.error == TT_SIGN_OK ? "ok" :
                sig.error == TT_SIGN_ERR_NULL_INPUT ? "null input" :
                sig.error == TT_SIGN_ERR_BAD_VERSION ? "bad version" : "alloc");
        tt_signatures_free(&sig);
        return 1;
    }

    if (debug_enabled()) printf("[2] Request built (tt_sign OK)\n\n");
    printf("X-Argus: %s\n", sig.x_argus);
    printf("X-Ladon: %s\n", sig.x_ladon);
    printf("X-Gorgon: %s\n", sig.x_gorgon);
    printf("X-Khronos: %s\n", sig.x_khronos);
    printf("X-TT-Request-Ticket: %s\n", sig.x_tt_request_ticket);
    printf("X-SS-Stub: %s\n", sig.x_ss_stub);

    url_param_t *up_params = (url_param_t *)malloc(params_count * sizeof(url_param_t));
    for (size_t i = 0; i < params_count; i++) {
        up_params[i].key = params[i].key;
        up_params[i].value = params[i].value;
    }
    char *query_str = url_encode_params(up_params, params_count);
    free(up_params);

    url_param_t *up_data = (url_param_t *)malloc(data_count * sizeof(url_param_t));
    for (size_t i = 0; i < data_count; i++) {
        up_data[i].key = data[i].key;
        up_data[i].value = data[i].value;
    }
    char *body_str = url_encode_params(up_data, data_count);
    free(up_data);

    char full_url[2048];
    snprintf(full_url, sizeof(full_url), "%s", TARGET_URL);
    if (query_str[0]) {
        strcat(full_url, "?");
        strcat(full_url, query_str);
    }
    free(query_str);

    if (debug_enabled()) {
        printf("[3] HTTP request (no sensitive values below)\n");
        printf("    method:      POST\n");
        printf("    url:         %.300s%s\n", full_url,
               strlen(full_url) > 300 ? "..." : "");
        printf("    content-type: application/x-www-form-urlencoded; charset=UTF-8\n");
        printf("    body-length: %zu\n", strlen(body_str));
        printf("    signature-headers: X-Argus / X-Ladon / X-Gorgon / "
               "X-Khronos / X-TT-Request-Ticket / X-SS-Stub\n\n");
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        free(body_str);
        tt_signatures_free(&sig);
        for (size_t i = 0; i < params_count; i++) { free(params[i].key); free(params[i].value); }
        free(params);
        for (size_t i = 0; i < data_count; i++) { free(data[i].key); free(data[i].value); }
        free(data);
        return 1;
    }

    struct response resp;
    resp.data = NULL;
    resp.size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, full_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body_str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body_str));

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Host: api16-normal-c-alisg.tiktokv.com");
    headers = curl_slist_append(headers, "Sdk-Version: 2");
    headers = curl_slist_append(headers, "Tt-Ticket-Guard-Iteration-Version: 0");
    headers = curl_slist_append(headers, "X-Tt-Dm-Status: login=0;ct=1;rt=6");
    headers = curl_slist_append(headers, "Tt-Ticket-Guard-Version: 3");
    headers = curl_slist_append(headers, "Passport-Sdk-Settings: x-tt-token");
    headers = curl_slist_append(headers, "Passport-Sdk-Sign: x-tt-token");
    headers = curl_slist_append(headers, "Passport-Sdk-Version: -1");
    headers = curl_slist_append(headers, "X-Tt-Bypass-Dp: 1");
    headers = curl_slist_append(headers, "X-Vc-Bdturing-Sdk-Version: 2.3.17.i18n");
    headers = curl_slist_append(headers, "Tt-Device-Guard-Iteration-Version: 1");
    headers = curl_slist_append(headers,
        "User-Agent: com.zhiliaoapp.musically/2024109030 "
        "(Linux; U; Android 13; en; WayDroid x86_64 Device; "
        "Build/TQ3A.230901.001;tt-ok/3.12.13.21)");
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded; charset=UTF-8");
    headers = curl_slist_append(headers, "Accept: */*");

    char hdr_argus[512], hdr_ladon[512], hdr_gorgon[1024],
         hdr_khronos[128], hdr_ticket[128], hdr_stub[128];
    snprintf(hdr_argus, sizeof(hdr_argus), "X-Argus: %s", sig.x_argus);
    snprintf(hdr_ladon, sizeof(hdr_ladon), "X-Ladon: %s", sig.x_ladon);
    snprintf(hdr_gorgon, sizeof(hdr_gorgon), "X-Gorgon: %s", sig.x_gorgon);
    snprintf(hdr_khronos, sizeof(hdr_khronos), "X-Khronos: %s", sig.x_khronos);
    snprintf(hdr_ticket, sizeof(hdr_ticket), "X-TT-Request-Ticket: %s", sig.x_tt_request_ticket);
    snprintf(hdr_stub, sizeof(hdr_stub), "X-SS-Stub: %s", sig.x_ss_stub);

    headers = curl_slist_append(headers, hdr_argus);
    headers = curl_slist_append(headers, hdr_ladon);
    headers = curl_slist_append(headers, hdr_gorgon);
    headers = curl_slist_append(headers, hdr_khronos);
    headers = curl_slist_append(headers, hdr_ticket);
    headers = curl_slist_append(headers, hdr_stub);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);

    printf("\n==================== HTTP RESPONSE ====================\n");

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        printf("==> NETWORK ERROR (request may never have been processed)\n");
    } else {
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        printf("HTTP Status: %ld\n", http_code);
        printf("Body Length: %zu\n", resp.size);
        if (resp.size == 0) {
            printf("<EMPTY>\n");
        } else {
            printf("Body:\n%s\n", resp.data);
        }

        printf("\n--- Application-level status ---\n");
        if (resp.size == 0) {
            printf("No response body; cannot determine application status.\n");
        } else {
            json_value_t *root = json_parse(resp.data);
            if (!root) {
                printf("Response body is not valid JSON; app status unknown.\n");
            } else {
                json_value_t *msg = json_get(root, "message");
                const char *msg_s = (msg && msg->type == JSON_STRING)
                                    ? msg->u.string_val : "";
                printf("app.message:  %s\n", msg_s[0] ? msg_s : "(missing)");

                json_value_t *data = json_get(root, "data");
                if (data && data->type == JSON_OBJECT) {
                    json_value_t *desc = json_get(data, "description");
                    if (desc && desc->type == JSON_STRING)
                        printf("app.message description:  %s\n", desc->u.string_val);
                    json_value_t *ec = json_get(data, "error_code");
                    if (ec && ec->type == JSON_NUMBER)
                        printf("app.error_code:           %.0f\n", ec->u.number_val);
                }

                if (msg_s && strcmp(msg_s, "success") == 0) {
                    printf("==> APPLICATION SUCCESS\n");
                } else {
                    printf("==> APPLICATION ERROR (server-side application "
                           "response; HTTP %ld does NOT mean success)\n", http_code);
                }
                json_free(root);
            }
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(resp.data);
    free(body_str);
    tt_signatures_free(&sig);

    for (size_t i = 0; i < params_count; i++) { free(params[i].key); free(params[i].value); }
    free(params);
    for (size_t i = 0; i < data_count; i++) { free(data[i].key); free(data[i].value); }
    free(data);

    return 0;
}
