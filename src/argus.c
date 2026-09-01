#include "tiktoksignature/argus.h"
#include "tiktoksignature/sm3.h"
#include "tiktoksignature/simon.h"
#include "tiktoksignature/protobuf.h"
#include "tiktoksignature/crypto_helpers.h"
#include "tiktoksignature/url_encode.h"
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static const uint8_t SIGN_KEY[32] = {
    0xac, 0x1a, 0xda, 0xae, 0x95, 0xa7, 0xaf, 0x94,
    0xa5, 0x11, 0x4a, 0xb3, 0xb3, 0xa9, 0x7d, 0xd8,
    0x00, 0x50, 0xaa, 0x0a, 0x39, 0x31, 0x4c, 0x40,
    0x52, 0x8c, 0xae, 0xc9, 0x52, 0x56, 0xc2, 0x8c
};

static const uint8_t SM3_OUTPUT_REF[32] = {
    0xfc, 0x78, 0xe0, 0xa9, 0x65, 0x7a, 0x0c, 0x74,
    0x8c, 0xe5, 0x15, 0x59, 0x90, 0x3c, 0xcf, 0x03,
    0x51, 0x0e, 0x51, 0xd3, 0xcf, 0xf2, 0x32, 0xd7,
    0x13, 0x43, 0xe8, 0x8a, 0x32, 0x1c, 0x53, 0x04
};

static uint8_t *body_hash(const char *stub, size_t *out_len) {
    uint8_t *out = (uint8_t *)malloc(6);
    *out_len = 6;
    if (!stub || !stub[0]) {
        uint8_t zero[16] = {0};
        uint8_t h[SM3_DIGEST_SIZE];
        sm3_hash(zero, 16, h);
        memcpy(out, h, 6);
        return out;
    }
    size_t decoded_len;
    uint8_t *decoded = hex_decode_string(stub, &decoded_len);
    uint8_t h[SM3_DIGEST_SIZE];
    sm3_hash(decoded, decoded_len, h);
    free(decoded);
    memcpy(out, h, 6);
    return out;
}

static uint8_t *query_hash(const char *query, size_t *out_len) {
    uint8_t *out = (uint8_t *)malloc(6);
    *out_len = 6;
    if (!query || !query[0]) {
        uint8_t zero[16] = {0};
        uint8_t h[SM3_DIGEST_SIZE];
        sm3_hash(zero, 16, h);
        memcpy(out, h, 6);
        return out;
    }
    uint8_t h[SM3_DIGEST_SIZE];
    sm3_hash((const uint8_t *)query, strlen(query), h);
    memcpy(out, h, 6);
    return out;
}

static uint8_t *encrypt_enc_pb(const uint8_t *data, size_t l, size_t *out_len) {
    *out_len = l;
    uint8_t *d = (uint8_t *)malloc(l);
    memcpy(d, data, l);
    uint8_t xor_array[8];
    memcpy(xor_array, d, 8);
    for (size_t i = 8; i < l; i++) {
        d[i] ^= xor_array[i % 8];
    }
    for (size_t i = 0, j = l - 1; i < j; i++, j--) {
        uint8_t tmp = d[i];
        d[i] = d[j];
        d[j] = tmp;
    }
    return d;
}

static uint8_t *pkcs7_pad(const uint8_t *data, size_t len, size_t block_size, size_t *out_len) {
    size_t pad_len = block_size - (len % block_size);
    *out_len = len + pad_len;
    uint8_t *p = (uint8_t *)malloc(*out_len);
    memcpy(p, data, len);
    for (size_t i = len; i < *out_len; i++) {
        p[i] = (uint8_t)pad_len;
    }
    return p;
}

static char *argus_encrypt(const uint8_t *bean, size_t bean_len) {
    size_t padded_len;
    uint8_t *protobuf = pkcs7_pad(bean, bean_len, 16, &padded_len);

    uint8_t key[32];
    memcpy(key, SM3_OUTPUT_REF, 32);
    uint64_t key_list[4];
    for (int i = 0; i < 4; i++) {
        key_list[i] = le64_read(key, i * 8);
    }

    uint8_t *enc_pb = (uint8_t *)malloc(padded_len);
    size_t enc_pb_pos = 0;
    for (size_t i = 0; i < padded_len / 16; i++) {
        uint64_t pt[2];
        pt[0] = le64_read(protobuf + i * 16, 0);
        pt[1] = le64_read(protobuf + i * 16, 8);
        uint64_t ct[2];
        simon_encrypt(pt, key_list, ct);
        uint8_t ct_bytes[16];
        le64_write(ct_bytes, 0, ct[0]);
        le64_write(ct_bytes, 1, ct[1]);
        memcpy(enc_pb + enc_pb_pos, ct_bytes, 16);
        enc_pb_pos += 16;
    }
    free(protobuf);

    uint8_t prefix1[8] = {0xf2, 0xf7, 0xfc, 0xff, 0xf2, 0xf7, 0xfc, 0xff};
    size_t buf_len = 8 + padded_len;
    uint8_t *buffer = (uint8_t *)malloc(buf_len);
    memcpy(buffer, prefix1, 8);
    memcpy(buffer + 8, enc_pb, padded_len);
    free(enc_pb);

    size_t enc_len;
    uint8_t *enc = encrypt_enc_pb(buffer, buf_len, &enc_len);
    free(buffer);

    uint8_t prefix2[9] = {0xa6, 0x6e, 0xad, 0x9f, 0x77, 0x01, 0xd0, 0x0c, 0x18};
    size_t with_prefix_len = 9 + enc_len;
    uint8_t *with_prefix = (uint8_t *)malloc(with_prefix_len);
    memcpy(with_prefix, prefix2, 9);
    memcpy(with_prefix + 9, enc, enc_len);
    free(enc);

    size_t with_suffix_len = with_prefix_len + 2;
    uint8_t *with_suffix = (uint8_t *)malloc(with_suffix_len);
    memcpy(with_suffix, with_prefix, with_prefix_len);
    free(with_prefix);
    with_suffix[with_prefix_len] = 'a';
    with_suffix[with_prefix_len + 1] = 'o';

    uint8_t key_md5[MD5_DIGEST_SIZE];
    md5_digest(SIGN_KEY, 16, key_md5);
    uint8_t iv_md5[MD5_DIGEST_SIZE];
    md5_digest(SIGN_KEY + 16, 16, iv_md5);

    /* AES-128-CBC encrypt with PKCS#7 padding (Java cipher.doFinal pads) */
    unsigned int ct_out_len = 0;
    uint8_t *ct_out = (uint8_t *)calloc(1, with_suffix_len + EVP_MAX_BLOCK_LENGTH);
    if (!ct_out) { free(with_suffix); return NULL; }

    int outl = 0;
    int suml = 0;
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    if (!cipher) { free(with_suffix); free(ct_out); return NULL; }

    EVP_EncryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key_md5, iv_md5);
    EVP_EncryptUpdate(cipher, ct_out + suml, &outl, with_suffix, (int)with_suffix_len);
    suml += outl;
    int finl = 0;
    EVP_EncryptFinal_ex(cipher, ct_out + suml, &finl);
    suml += finl;
    ct_out_len = (unsigned int)suml;
    EVP_CIPHER_CTX_free(cipher);
    free(with_suffix);

    size_t result_len = 2 + ct_out_len;
    uint8_t *result = (uint8_t *)malloc(result_len);
    result[0] = 0xf2;
    result[1] = 0x81;
    memcpy(result + 2, ct_out, ct_out_len);
    free(ct_out);

    size_t b64_len = 4 * ((result_len + 2) / 3) + 1;
    char *b64 = (char *)malloc(b64_len);
    /* Manual base64 encode */
    const char *tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < result_len; i += 3) {
        uint32_t n = (uint32_t)result[i] << 16;
        if (i + 1 < result_len) n |= (uint32_t)result[i + 1] << 8;
        if (i + 2 < result_len) n |= (uint32_t)result[i + 2];
        b64[o++] = tbl[(n >> 18) & 0x3F];
        b64[o++] = tbl[(n >> 12) & 0x3F];
        b64[o++] = (i + 1 < result_len) ? tbl[(n >> 6) & 0x3F] : '=';
        b64[o++] = (i + 2 < result_len) ? tbl[n & 0x3F] : '=';
    }
    b64[o] = '\0';
    free(result);
    return b64;
}

char *argus_get_sign(const char *query, const char *stub, int64_t timestamp,
                     int aid, int license_id, int platform,
                     const char *sec_device_id, const char *sdk_version,
                     int sdk_version_int, int32_t rand_val) {
    size_t qp_count;
    query_param_t *qp = parse_query_params(query, &qp_count);

    const char *device_id = "";
    const char *version_name = "";
    for (size_t i = 0; i < qp_count; i++) {
        if (strcmp(qp[i].key, "device_id") == 0) device_id = qp[i].value;
        if (strcmp(qp[i].key, "version_name") == 0) version_name = qp[i].value;
    }

    int32_t rand_int;
    if (rand_val >= 0) {
        rand_int = rand_val;
    } else {
        rand_int = (int32_t)crypto_rand_uint31();
    }

    char aid_str[32];
    snprintf(aid_str, sizeof(aid_str), "%d", aid);
    char lic_str[32];
    snprintf(lic_str, sizeof(lic_str), "%d", license_id);

    uint8_t bh[6], qh[6];
    size_t bh_len, qh_len;
    uint8_t *bh_raw = body_hash(stub, &bh_len);
    uint8_t *qh_raw = query_hash(query, &qh_len);
    memcpy(bh, bh_raw, 6);
    memcpy(qh, qh_raw, 6);
    free(bh_raw);
    free(qh_raw);

    pb_field_t fields[21];
    pb_field_t inner15_fields[4];
    pb_field_t inner23_fields[3];

    uint8_t zero8[8] = {0};
    uint64_t ts_shifted = ((uint64_t)timestamp) << 1;
    uint64_t field1_val = (0x20200929ULL << 1);

    size_t fi = 0;
    fields[fi++] = (pb_field_t){1, PB_KIND_VARINT, field1_val, NULL, 0};
    fields[fi++] = (pb_field_t){2, PB_KIND_VARINT, 2, NULL, 0};
    fields[fi++] = (pb_field_t){3, PB_KIND_VARINT, (uint64_t)((int32_t)rand_int & 0x7FFFFFFF), NULL, 0};
    fields[fi++] = (pb_field_t){4, PB_KIND_STRING, 0, (const uint8_t *)aid_str, strlen(aid_str)};
    fields[fi++] = (pb_field_t){5, PB_KIND_STRING, 0, (const uint8_t *)device_id, strlen(device_id)};
    fields[fi++] = (pb_field_t){6, PB_KIND_STRING, 0, (const uint8_t *)lic_str, strlen(lic_str)};
    fields[fi++] = (pb_field_t){7, PB_KIND_STRING, 0, (const uint8_t *)version_name, strlen(version_name)};
    fields[fi++] = (pb_field_t){8, PB_KIND_STRING, 0, (const uint8_t *)sdk_version, strlen(sdk_version)};
    fields[fi++] = (pb_field_t){9, PB_KIND_VARINT, (uint64_t)sdk_version_int, NULL, 0};
    fields[fi++] = (pb_field_t){10, PB_KIND_STRING, 0, zero8, 8};
    fields[fi++] = (pb_field_t){11, PB_KIND_VARINT, (uint64_t)platform, NULL, 0};
    fields[fi++] = (pb_field_t){12, PB_KIND_VARINT, ts_shifted, NULL, 0};
    fields[fi++] = (pb_field_t){13, PB_KIND_STRING, 0, bh, 6};
    fields[fi++] = (pb_field_t){14, PB_KIND_STRING, 0, qh, 6};

    inner15_fields[0] = (pb_field_t){1, PB_KIND_VARINT, 1, NULL, 0};
    inner15_fields[1] = (pb_field_t){2, PB_KIND_VARINT, 1, NULL, 0};
    inner15_fields[2] = (pb_field_t){3, PB_KIND_VARINT, 1, NULL, 0};
    inner15_fields[3] = (pb_field_t){7, PB_KIND_VARINT, 3348294860ULL, NULL, 0};

    uint8_t inner15_buf[64];
    size_t inner15_len = pb_serialize(inner15_fields, 4, inner15_buf, sizeof(inner15_buf));
    fields[fi++] = (pb_field_t){15, PB_KIND_STRING, 0, inner15_buf, inner15_len};

    fields[fi++] = (pb_field_t){16, PB_KIND_STRING, 0, (const uint8_t *)sec_device_id, strlen(sec_device_id)};

    uint8_t none_str[] = "none";
    fields[fi++] = (pb_field_t){20, PB_KIND_STRING, 0, none_str, 4};
    fields[fi++] = (pb_field_t){21, PB_KIND_VARINT, 738, NULL, 0};

    inner23_fields[0] = (pb_field_t){1, PB_KIND_STRING, 0, (const uint8_t *)"NX551J", 6};
    inner23_fields[1] = (pb_field_t){2, PB_KIND_VARINT, 8196, NULL, 0};
    inner23_fields[2] = (pb_field_t){4, PB_KIND_VARINT, 2162219008ULL, NULL, 0};

    uint8_t inner23_buf[64];
    size_t inner23_len = pb_serialize(inner23_fields, 3, inner23_buf, sizeof(inner23_buf));
    fields[fi++] = (pb_field_t){23, PB_KIND_STRING, 0, inner23_buf, inner23_len};

    fields[fi++] = (pb_field_t){25, PB_KIND_VARINT, 2, NULL, 0};

    uint8_t bean_buf[4096];
    size_t bean_len = pb_serialize(fields, fi, bean_buf, sizeof(bean_buf));

    free_query_params(qp, qp_count);

    return argus_encrypt(bean_buf, bean_len);
}
