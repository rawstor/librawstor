#ifndef RAWSTOR_UUID_H
#define RAWSTOR_UUID_H


#include <stdint.h>


typedef struct {
    uint8_t bytes[16];
} rawstor_uuid;

typedef char rawstor_uuid_string[37];


int rawstor_uuid7_init(rawstor_uuid *uuid);

void rawstor_uuid_to_string(const rawstor_uuid *uuid, rawstor_uuid_string *s);

int rawstor_uuid_from_string(const char *s, rawstor_uuid *uuid);


#endif // RAWSTOR_UUID_H
