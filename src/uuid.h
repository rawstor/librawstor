#ifndef RAWSTOR_UUID_H
#define RAWSTOR_UUID_H


#include <stdint.h>


typedef struct {
    uint8_t bytes[16];
} RawstorUUID;

typedef char RawstorUUIDString[37];


int rawstor_uuid7_init(RawstorUUID *uuid);

void rawstor_uuid_to_string(const RawstorUUID *uuid, RawstorUUIDString *s);

int rawstor_uuid_from_string(const char *s, RawstorUUID *uuid);


#endif // RAWSTOR_UUID_H
