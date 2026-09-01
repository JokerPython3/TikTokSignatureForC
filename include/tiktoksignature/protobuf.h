#ifndef TIKTOK_PROTOBUF_H
#define TIKTOK_PROTOBUF_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t idx;
    int kind;
    uint64_t varint;
    const uint8_t *data;
    size_t data_len;
} pb_field_t;

#define PB_KIND_VARINT 0
#define PB_KIND_STRING 2

size_t pb_serialize(const pb_field_t *fields, size_t count, uint8_t *out, size_t out_cap);
size_t pb_write_varint_raw(uint8_t *out, size_t out_cap, uint64_t vint);
size_t pb_field_varint(uint64_t idx, uint64_t value, pb_field_t *out);
size_t pb_field_string(uint64_t idx, const uint8_t *data, size_t len, pb_field_t *out);

#endif
