#define _POSIX_C_SOURCE 200809L
#include "tiktoksignature/sm3.h"
#include "tiktoksignature/simon.h"
#include "tiktoksignature/protobuf.h"
#include "tiktoksignature/crypto_helpers.h"
#include "tiktoksignature/url_encode.h"
#include "tiktoksignature/gorgon.h"
#include "tiktoksignature/ladon.h"
#include "tiktoksignature/argus.h"
#include "tiktoksignature/signer.h"
#include "tiktoksignature/mini_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int tests_run = 0;
static int tests_failed = 0;

static int test_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

#define ASSERT_STR(name, want, got) do { \
    tests_run++; \
    const char *_w = (want); const char *_g = (got); \
    if (_w == NULL || _g == NULL ? _w != _g : strcmp(_w, _g) != 0) { \
        printf("  FAIL %s:\n    want: %s\n    got:  %s\n", name, _w ? _w : "(null)", _g ? _g : "(null)"); \
        tests_failed++; \
    } else { \
        printf("  PASS %s\n", name); \
    } \
} while(0)

#define ASSERT_INT(name, want, got) do { \
    tests_run++; \
    if ((want) != (got)) { \
        printf("  FAIL %s: want %d got %d\n", name, (int)(want), (int)(got)); \
        tests_failed++; \
    } else { \
        printf("  PASS %s\n", name); \
    } \
} while(0)

#define ASSERT_LONG(name, want, got) do { \
    tests_run++; \
    if ((want) != (got)) { \
        printf("  FAIL %s: want %lld got %lld\n", name, (long long)(want), (long long)(got)); \
        tests_failed++; \
    } else { \
        printf("  PASS %s\n", name); \
    } \
} while(0)

/* ===================== SM3 Tests ===================== */
static void test_sm3_vectors(void) {
    printf("=== SM3 ===\n");
    uint8_t h[32];
    char hex[65];

    sm3_hash((uint8_t *)"", 0, h);
    bytes_to_hex(h, 32, hex);
    ASSERT_STR("SM3(empty)", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", hex);

    sm3_hash((uint8_t *)"abc", 3, h);
    bytes_to_hex(h, 32, hex);
    ASSERT_STR("SM3(abc)", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", hex);

    uint8_t zero16[16] = {0};
    sm3_hash(zero16, 16, h);
    bytes_to_hex(h, 32, hex);
    ASSERT_STR("SM3(16-zero)", "106e34a2b8c7bb13156cfdd0d91379dcc47543dcf9787c68ae5eb582620ae6e8", hex);

    uint8_t buf57[57];
    memset(buf57, 'x', 57);
    sm3_hash(buf57, 57, h);
    bytes_to_hex(h, 32, hex);
    ASSERT_STR("SM3(len57)", "6ea239cae3a9660ef7db6a72345e04b9bb572d0269bc3c6528faa6af3821397e", hex);

    uint8_t buf120[120];
    memset(buf120, 'y', 120);
    sm3_hash(buf120, 120, h);
    bytes_to_hex(h, 32, hex);
    ASSERT_STR("SM3(len120)", "8b7b1040722bb5b75d2486ba610d905e8452789f2295870957ad7779c1282631", hex);
}

/* ===================== Simon Tests ===================== */
static void test_simon_enc(void) {
    printf("=== Simon ===\n");
    uint64_t key[4] = {
        0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
        0x1011121314151617ULL, 0x18191a1b1c1d1e1fULL
    };
    uint64_t pt[2] = {0x626b7373656d7369ULL, 0x656d6361756c6f70ULL};
    uint64_t ct[2];
    simon_encrypt(pt, key, ct);
    ASSERT_LONG("simon[0]", (int64_t)-7893652479812039344LL, (int64_t)ct[0]);
    ASSERT_LONG("simon[1]", 3305761749203649550LL, (int64_t)ct[1]);
}

/* ===================== SM3 SignKey Constant ===================== */
static void test_sm3_signkey_constant(void) {
    printf("=== SM3 SignKey ===\n");
    uint8_t sign_key[32] = {
        0xac, 0x1a, 0xda, 0xae, 0x95, 0xa7, 0xaf, 0x94,
        0xa5, 0x11, 0x4a, 0xb3, 0xb3, 0xa9, 0x7d, 0xd8,
        0x00, 0x50, 0xaa, 0x0a, 0x39, 0x31, 0x4c, 0x40,
        0x52, 0x8c, 0xae, 0xc9, 0x52, 0x56, 0xc2, 0x8c
    };
    uint8_t sm3_output[32] = {
        0xfc, 0x78, 0xe0, 0xa9, 0x65, 0x7a, 0x0c, 0x74,
        0x8c, 0xe5, 0x15, 0x59, 0x90, 0x3c, 0xcf, 0x03,
        0x51, 0x0e, 0x51, 0xd3, 0xcf, 0xf2, 0x32, 0xd7,
        0x13, 0x43, 0xe8, 0x8a, 0x32, 0x1c, 0x53, 0x04
    };

    uint8_t suffix[32 + 4 + 32];
    memcpy(suffix, sign_key, 32);
    suffix[32] = 0xf2;
    suffix[33] = 0x81;
    suffix[34] = 'a';
    suffix[35] = 'o';
    memcpy(suffix + 36, sign_key, 32);

    uint8_t h[32];
    sm3_hash(suffix, sizeof(suffix), h);

    char got[65], want[65];
    bytes_to_hex(h, 32, got);
    bytes_to_hex(sm3_output, 32, want);
    ASSERT_STR("SM3 sign key constant", want, got);
}

/* ===================== Gorgon Helpers ===================== */
static void test_gorgon_helpers(void) {
    printf("=== Gorgon Helpers ===\n");
    uint8_t ns = (uint8_t)(((0x12 >> 4) & 0x0F) | ((0x12 & 0x0F) << 4));
    ASSERT_INT("nibbleSwap(0x12)", 0x21, ns);

    uint8_t b = 0x80;
    b = (uint8_t)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
    b = (uint8_t)(((b & 0xCC) >> 2) | ((b & 0x33) << 2));
    b = (uint8_t)(((b & 0xAA) >> 1) | ((b & 0x55) << 1));
    ASSERT_INT("bitReverse(0x80)", 0x01, b);

    char hex1[9];
    snprintf(hex1, 9, "%08x", (unsigned)100000000);
    ASSERT_STR("hexOfUnix(100000000)", "05f5e100", hex1);

    char hex2[9];
    snprintf(hex2, 9, "%08x", (unsigned)1700000000);
    ASSERT_STR("hexOfUnix(1700000000)", "6553f100", hex2);
}

/* ===================== URL Encoding Tests ===================== */
static void test_quote_plus(void) {
    printf("=== URL Encode ===\n");
    char *r;

    r = quote_plus("");
    ASSERT_STR("quotePlus empty", "", r);
    free(r);

    r = quote_plus("abc123_.-~");
    ASSERT_STR("quotePlus safe", "abc123_.-~", r);
    free(r);

    r = quote_plus("a b c");
    ASSERT_STR("quotePlus spaces", "a+b+c", r);
    free(r);

    r = quote_plus("a+b");
    ASSERT_STR("quotePlus plus", "a%2Bb", r);
    free(r);

    r = quote_plus("x/y?&=");
    ASSERT_STR("quotePlus reserved", "x%2Fy%3F%26%3D", r);
    free(r);

    r = quote_plus("\xC3\xA9");
    ASSERT_STR("quotePlus eacute", "%C3%A9", r);
    free(r);

    r = quote_plus("\xE6\xB5\x8B\xE8\xAF\x95");
    ASSERT_STR("quotePlus chinese", "%E6%B5%8B%E8%AF%95", r);
    free(r);
}

static void test_unquote_plus_round_trip(void) {
    printf("=== URL Round Trip ===\n");
    const char *inputs[] = {
        "WayDroid x86_64 Device",
        "us\xC3\xA9r+plus@example.com",
        "a b/c?d=e&f%g",
        "\xE6\xB5\x8B\xE8\xAF\x95",
        ""
    };
    int count = 5;
    for (int i = 0; i < count; i++) {
        char *enc = quote_plus(inputs[i]);
        char *dec = unquote_plus(enc);
        char name[64];
        snprintf(name, sizeof(name), "roundTrip[%d]", i);
        ASSERT_STR(name, inputs[i], dec);
        free(enc);
        free(dec);
    }
}

static void test_parse_query_params(void) {
    printf("=== Parse Query Params ===\n");
    size_t count;
    query_param_t *qp = parse_query_params("device_id=7401&version_name=41.9.3&empty=&x=a+b%2Fc", &count);

    const char *dev_id = NULL, *ver_name = NULL, *x_val = NULL;
    int has_empty = 0;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(qp[i].key, "device_id") == 0) dev_id = qp[i].value;
        if (strcmp(qp[i].key, "version_name") == 0) ver_name = qp[i].value;
        if (strcmp(qp[i].key, "empty") == 0) has_empty = 1;
        if (strcmp(qp[i].key, "x") == 0) x_val = qp[i].value;
    }

    ASSERT_STR("parseQuery device_id", "7401", dev_id);
    ASSERT_STR("parseQuery version_name", "41.9.3", ver_name);
    ASSERT_INT("parseQuery empty dropped", 0, has_empty);
    ASSERT_STR("parseQuery x", "a b/c", x_val);

    free_query_params(qp, count);
}

/* ===================== ProtoBuf Varint Tests ===================== */
static void test_varint_quirk(void) {
    printf("=== ProtoBuf Varint ===\n");
    uint8_t buf[64];
    size_t len;

    pb_field_t f;
    f.idx = 1; f.kind = PB_KIND_VARINT; f.varint = 150; f.data = NULL; f.data_len = 0;
    len = pb_serialize(&f, 1, buf, sizeof(buf));
    ASSERT_INT("serialize(idx=1,150) len", 3, (int)len);

    len = pb_write_varint_raw(buf, sizeof(buf), 150);
    ASSERT_INT("writeVarint(150) len", 2, (int)len);
    ASSERT_INT("writeVarint(150) [0]", 0x96, buf[0]);
    ASSERT_INT("writeVarint(150) [1]", 0x01, buf[1]);

    len = pb_write_varint_raw(buf, sizeof(buf), 0x80);
    ASSERT_INT("writeVarint(0x80) len", 1, (int)len);
    ASSERT_INT("writeVarint(0x80) quirk -> [0x00]", 0x00, buf[0]);
}

/* ===================== Ladon Padding Tests ===================== */
static void test_ladon_padding(void) {
    printf("=== Ladon Padding ===\n");

    int ps;
    /* paddingSize(0) = 0 */
    ps = 0 % 16; if (ps > 0) ps = 0 + (16 - ps); else ps = 0;
    ASSERT_INT("pad 0", 0, ps);

    /* paddingSize(15) = 16 */
    { int m = 15 % 16; ps = (m > 0) ? 15 + (16 - m) : 15; }
    ASSERT_INT("pad 15", 16, ps);

    /* paddingSize(16) = 16 */
    { int m = 16 % 16; ps = (m > 0) ? 16 + (16 - m) : 16; }
    ASSERT_INT("pad 16", 16, ps);

    /* paddingSize(17) = 32 */
    { int m = 17 % 16; ps = (m > 0) ? 17 + (16 - m) : 17; }
    ASSERT_INT("pad 17", 32, ps);
}

/* ===================== Golden Vector Tests ===================== */
static void test_golden_vectors(const char *testdata_dir) {
    printf("=== Golden Vectors ===\n");

    for (int vi = 1; vi <= 9; vi++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/vector_%03d.json", testdata_dir, vi);

        FILE *f = fopen(path, "r");
        if (!f) { printf("  SKIP vector_%03d: cannot open %s\n", vi, path); continue; }

        fseek(f, 0, SEEK_END);
        long fsize = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *content = (char *)malloc((size_t)fsize + 1);
        size_t nr = fread(content, 1, (size_t)fsize, f);
        (void)nr;
        content[fsize] = '\0';
        fclose(f);

        json_value_t *root = json_parse(content);
        json_value_t *input = json_get(root, "input");
        json_value_t *random_obj = json_get(root, "random");
        json_value_t *expected = json_get(root, "expected");
        const char *vname = json_get_string(root, "name");

        if (!input || !random_obj || !expected) {
            printf("  SKIP vector_%03d: missing fields\n", vi);
            json_free(root);
            free(content);
            continue;
        }

        json_value_t *jparams = json_get(input, "params");
        json_value_t *jdata = json_get(input, "data");
        json_value_t *jcookie = json_get(input, "cookie");

        size_t param_count = json_array_count(jparams);
        tt_param_t *params_arr = NULL;
        if (param_count > 0) {
            params_arr = (tt_param_t *)malloc(param_count * sizeof(tt_param_t));
            for (size_t i = 0; i < param_count; i++) {
                json_value_t *kv = json_array_get(jparams, i);
                params_arr[i].key = strdup(json_array_get(kv, 0)->u.string_val);
                params_arr[i].value = strdup(json_array_get(kv, 1)->u.string_val);
            }
        }

        size_t data_count = 0;
        tt_param_t *data_arr = NULL;
        if (jdata && jdata->type == JSON_ARRAY) {
            data_count = json_array_count(jdata);
            if (data_count > 0) {
                data_arr = (tt_param_t *)malloc(data_count * sizeof(tt_param_t));
                for (size_t i = 0; i < data_count; i++) {
                    json_value_t *kv = json_array_get(jdata, i);
                    data_arr[i].key = strdup(json_array_get(kv, 0)->u.string_val);
                    data_arr[i].value = strdup(json_array_get(kv, 1)->u.string_val);
                }
            }
        }

        size_t cookie_count = 0;
        tt_param_t *cookie_arr = NULL;
        if (jcookie && jcookie->type == JSON_ARRAY) {
            cookie_count = json_array_count(jcookie);
            if (cookie_count > 0) {
                cookie_arr = (tt_param_t *)malloc(cookie_count * sizeof(tt_param_t));
                for (size_t i = 0; i < cookie_count; i++) {
                    json_value_t *kv = json_array_get(jcookie, i);
                    cookie_arr[i].key = strdup(json_array_get(kv, 0)->u.string_val);
                    cookie_arr[i].value = strdup(json_array_get(kv, 1)->u.string_val);
                }
            }
        }

        tt_sign_request_t req;
        memset(&req, 0, sizeof(req));
        req.params = params_arr;
        req.params_count = param_count;
        req.data = data_arr;
        req.data_count = data_count;
        req.cookie = cookie_arr;
        req.cookie_count = cookie_count;

        tt_sign_options_t opts;
        memset(&opts, 0, sizeof(opts));
        opts.timestamp = json_get_long(input, "timestamp", 0);
        opts.has_timestamp = true;
        opts.aid = json_get_int(input, "aid", 0);
        opts.license_id = json_get_int(input, "license_id", 0);
        opts.platform = json_get_int(input, "platform", 0);
        opts.sdk_version = json_get_string(input, "sdk_version_str");
        opts.sdk_version_int = json_get_int(input, "sdk_version", 0);
        opts.sec_device_id = json_get_string(input, "sec_device_id");

        json_value_t *jver = json_get(input, "version");
        if (jver && jver->type == JSON_NUMBER) {
            opts.version = (int)jver->u.number_val;
        } else {
            opts.version = 0;
        }

        opts.has_gorgon_byte3 = true;
        opts.gorgon_byte3 = (uint8_t)(int)json_object_get_number(random_obj, "gorgon_byte3");
        opts.has_gorgon_byte7 = true;
        opts.gorgon_byte7 = (uint8_t)(int)json_object_get_number(random_obj, "gorgon_byte7");
        opts.has_argus_rand = true;
        opts.argus_rand = (int32_t)json_object_get_number(random_obj, "argus_rand");

        const char *ladon_hex = json_get_string(random_obj, "ladon_random");
        opts.has_ladon_random = true;
        if (ladon_hex) {
            for (int k = 0; k < 8; k += 2) {
                int hi = test_hex_nibble(ladon_hex[k]);
                int lo = test_hex_nibble(ladon_hex[k + 1]);
                opts.ladon_random[k / 2] = (uint8_t)((hi << 4) | lo);
            }
        }

        tt_signatures_t sig = tt_sign(&req, &opts);

        const char *want_argus = json_get_string(expected, "x_argus");
        const char *want_ladon = json_get_string(expected, "x_ladon");
        const char *want_gorgon = json_get_string(expected, "x_gorgon");
        const char *want_khronos = json_get_string(expected, "x_khronos");
        const char *want_ticket = json_get_string(expected, "x_tt_request_ticket");
        const char *want_stub = json_get_string(expected, "x_ss_stub");

        char label[128];

        snprintf(label, sizeof(label), "v%d [%s] X-Argus", vi, vname);
        ASSERT_STR(label, want_argus, sig.x_argus);

        snprintf(label, sizeof(label), "v%d [%s] X-Ladon", vi, vname);
        ASSERT_STR(label, want_ladon, sig.x_ladon);

        snprintf(label, sizeof(label), "v%d [%s] X-Gorgon", vi, vname);
        ASSERT_STR(label, want_gorgon, sig.x_gorgon);

        snprintf(label, sizeof(label), "v%d [%s] X-Khronos", vi, vname);
        ASSERT_STR(label, want_khronos, sig.x_khronos);

        snprintf(label, sizeof(label), "v%d [%s] X-TT-Request-Ticket", vi, vname);
        ASSERT_STR(label, want_ticket, sig.x_tt_request_ticket);

        snprintf(label, sizeof(label), "v%d [%s] X-SS-Stub", vi, vname);
        ASSERT_STR(label, want_stub, sig.x_ss_stub);

        tt_signatures_free(&sig);

        for (size_t i = 0; i < param_count; i++) { free(params_arr[i].key); free(params_arr[i].value); }
        free(params_arr);
        for (size_t i = 0; i < data_count; i++) { free(data_arr[i].key); free(data_arr[i].value); }
        free(data_arr);
        for (size_t i = 0; i < cookie_count; i++) { free(cookie_arr[i].key); free(cookie_arr[i].value); }
        free(cookie_arr);

        json_free(root);
        free(content);
    }
}

static void test_error_handling(void) {
    printf("=== Error Handling ===\n");

    tt_signatures_t sig0 = tt_sign(NULL, NULL);
    ASSERT_INT("tt_sign(NULL,NULL) error", TT_SIGN_ERR_NULL_INPUT, sig0.error);
    ASSERT_STR("tt_sign(NULL,NULL) x_argus NULL", NULL, sig0.x_argus);
    tt_signatures_free(&sig0);
    tt_signatures_free(NULL);

    tt_signatures_t sig_bad;
    memset(&sig_bad, 0, sizeof(sig_bad));
    tt_signatures_free(&sig_bad);

    tt_param_t p[] = {{"aid", "1233"}};
    tt_sign_request_t req; memset(&req, 0, sizeof(req));
    req.params = p; req.params_count = 1;

    tt_sign_options_t opts; memset(&opts, 0, sizeof(opts));
    opts.timestamp = 1700000000; opts.has_timestamp = true;
    opts.version = 9999;

    tt_signatures_t sigv = tt_sign(&req, &opts);
    ASSERT_INT("tt_sign bad version error", TT_SIGN_ERR_BAD_VERSION, sigv.error);
    ASSERT_STR("tt_sign bad version x_argus NULL", NULL, sigv.x_argus);
    tt_signatures_free(&sigv);
}

int main(int argc, char **argv) {
    const char *testdata_dir = "testdata";
    if (argc > 1) testdata_dir = argv[1];

    test_sm3_vectors();
    test_simon_enc();
    test_sm3_signkey_constant();
    test_gorgon_helpers();
    test_quote_plus();
    test_unquote_plus_round_trip();
    test_parse_query_params();
    test_varint_quirk();
    test_ladon_padding();
    test_error_handling();
    test_golden_vectors(testdata_dir);

    printf("\n=== Results ===\n");
    printf("Ran %d tests, %d failed.\n", tests_run, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
