#ifndef RAWSTD_UUID_H
#define RAWSTD_UUID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct RawstdUUID {
    uint8_t bytes[16];
};

typedef char RawstdUUIDString[37];

int rawstd_uuid7_init(struct RawstdUUID* uuid);

int rawstd_uuid_from_string(struct RawstdUUID* uuid, const char* s);

void rawstd_uuid_to_string(const struct RawstdUUID* uuid, RawstdUUIDString* s);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_UUID_H
