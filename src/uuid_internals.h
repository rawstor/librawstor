#ifndef RAWSTOR_UUID_INTERNALS_H
#define RAWSTOR_UUID_INTERNALS_H


#include "uuid.h"

#include <stdint.h>


uint64_t rawstor_uuid7_get_timestamp(const RawstorUUID *uuid);

int rawstor_uuid7_set_timestamp(RawstorUUID *uuid, uint64_t ts);

uint64_t rawstor_uuid7_get_counter(const RawstorUUID *uuid);

int rawstor_uuid7_set_counter(RawstorUUID *uuid, uint64_t counter);

uint8_t rawstor_uuid_get_version(RawstorUUID *uuid);

void rawstor_uuid_set_version(RawstorUUID *uuid, uint8_t version);

uint8_t rawstor_uuid_get_variant(RawstorUUID *uuid);

void rawstor_uuid_set_variant(RawstorUUID *uuid, uint8_t variant);


#endif // RAWSTOR_UUID_INTERNALS_H
