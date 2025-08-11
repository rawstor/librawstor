#ifndef RAWSTOR_UUID_H
#define RAWSTOR_UUID_H

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint8_t bytes[16];
} RawstorUUID;

typedef char RawstorUUIDString[37];


int rawstor_uuid_from_string(RawstorUUID *uuid, const char *s);

void rawstor_uuid_to_string(const RawstorUUID *uuid, RawstorUUIDString *s);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_UUID_H
