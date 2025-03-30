#ifndef RAWSTOR_UUID_INTERNALS_H
#define RAWSTOR_UUID_INTERNALS_H


#include "uuid.h"

#include <stdint.h>


uint64_t rawstor_uuid7_get_timestamp(const rawstor_uuid *uuid);

int rawstor_uuid7_set_timestamp(rawstor_uuid *uuid, uint64_t ts);

uint64_t rawstor_uuid7_get_counter(const rawstor_uuid *uuid);

int rawstor_uuid7_set_counter(rawstor_uuid *uuid, uint64_t counter);

uint8_t rawstor_uuid_get_version(rawstor_uuid *uuid);

void rawstor_uuid_set_version(rawstor_uuid *uuid, uint8_t version);

uint8_t rawstor_uuid_get_variant(rawstor_uuid *uuid);

void rawstor_uuid_set_variant(rawstor_uuid *uuid, uint8_t variant);


#endif // RAWSTOR_UUID_INTERNALS_H
