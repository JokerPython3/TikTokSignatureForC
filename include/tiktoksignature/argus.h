#ifndef TIKTOK_ARGUS_H
#define TIKTOK_ARGUS_H

#include <stdint.h>
#include <stdbool.h>

char *argus_get_sign(const char *query, const char *stub, int64_t timestamp,
                     int aid, int license_id, int platform,
                     const char *sec_device_id, const char *sdk_version,
                     int sdk_version_int, int32_t rand_val);

#endif
