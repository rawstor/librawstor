#ifndef RAWSTORSTD_UUID_H
#define RAWSTORSTD_UUID_H

#include <rawstor.h>

#include <stdint.h>


// defined in rawstor.h
// typedef struct {
//     uint8_t bytes[16];
// } RawstorUUID;

// defined in rawstor.h
// typedef char RawstorUUIDString[37];


int rawstor_uuid7_init(RawstorUUID *uuid);

int rawstor_uuid_from_string(RawstorUUID *uuid, const char *s);

void rawstor_uuid_to_string(const RawstorUUID *uuid, RawstorUUIDString *s);


#endif // RAWSTORSTD_UUID_H
