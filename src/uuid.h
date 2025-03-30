#ifndef RAWSTOR_UUID_H
#define RAWSTOR_UUID_H


#include <stdint.h>


typedef struct {
    uint8_t bytes[16];
} rawstor_uuid;


int rawstor_uuid7_init(rawstor_uuid *uuid);

void rawstor_uuid_to_string(const rawstor_uuid *uuid, char (*s)[37]);

int rawstor_uuid_from_string(const char *s, rawstor_uuid *uuid);


#endif // RAWSTOR_UUID_H
