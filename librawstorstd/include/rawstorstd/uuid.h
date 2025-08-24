#ifndef RAWSTORSTD_UUID_H
#define RAWSTORSTD_UUID_H

#include <rawstor.h>

#include <stdint.h>


// defined in rawstor.h
// struct RawstorUUID {
//     uint8_t bytes[16];
// };

// defined in rawstor.h
// typedef char RawstorUUIDString[37];


int rawstor_uuid7_init(struct RawstorUUID *uuid);

int rawstor_uuid_from_string(struct RawstorUUID *uuid, const char *s);

void rawstor_uuid_to_string(
    const struct RawstorUUID *uuid, RawstorUUIDString *s);


#endif // RAWSTORSTD_UUID_H
