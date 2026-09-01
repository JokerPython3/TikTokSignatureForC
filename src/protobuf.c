#include "tiktoksignature/protobuf.h"
#include <string.h>

static size_t write_varint(uint8_t *out, size_t pos, uint64_t vint) {
    vint &= 0xFFFFFFFFULL;
    while (vint > 0x80) {
        if (pos < SIZE_MAX) {
            out[pos] = (uint8_t)((vint & 0x7F) | 0x80);
        }
        pos++;
        vint >>= 7;
    }
    if (pos < SIZE_MAX) {
        out[pos] = (uint8_t)(vint & 0x7F);
    }
    pos++;
    return pos;
}

size_t pb_write_varint_raw(uint8_t *out, size_t out_cap, uint64_t vint) {
    (void)out_cap;
    return write_varint(out, 0, vint);
}

size_t pb_serialize(const pb_field_t *fields, size_t count, uint8_t *out, size_t out_cap) {
    size_t pos = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t key = (fields[i].idx << 3) | ((uint64_t)fields[i].kind & 7);
        pos = write_varint(out, pos, key);
        if (fields[i].kind == PB_KIND_VARINT) {
            pos = write_varint(out, pos, fields[i].varint);
        } else if (fields[i].kind == PB_KIND_STRING) {
            pos = write_varint(out, pos, fields[i].data_len);
            if (pos + fields[i].data_len <= out_cap) {
                memcpy(out + pos, fields[i].data, fields[i].data_len);
            }
            pos += fields[i].data_len;
        }
    }
    return pos;
}

size_t pb_field_varint(uint64_t idx, uint64_t value, pb_field_t *out) {
    out->idx = idx;
    out->kind = PB_KIND_VARINT;
    out->varint = value;
    out->data = NULL;
    out->data_len = 0;
    return 1;
}

size_t pb_field_string(uint64_t idx, const uint8_t *data, size_t len, pb_field_t *out) {
    out->idx = idx;
    out->kind = PB_KIND_STRING;
    out->varint = 0;
    out->data = data;
    out->data_len = len;
    return 1;
}
