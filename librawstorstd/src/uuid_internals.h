#ifndef RAWSTOR_UUID_STD_INTERNALS_H
#define RAWSTOR_UUID_STD_INTERNALS_H

#include "rawstorstd/uuid.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rawstor_uuid7_get_timestamp(const struct RawstorUUID* uuid);

int rawstor_uuid7_set_timestamp(struct RawstorUUID* uuid, uint64_t ts);

uint64_t rawstor_uuid7_get_counter(const struct RawstorUUID* uuid);

int rawstor_uuid7_set_counter(struct RawstorUUID* uuid, uint64_t counter);

uint8_t rawstor_uuid_get_version(struct RawstorUUID* uuid);

void rawstor_uuid_set_version(struct RawstorUUID* uuid, uint8_t version);

uint8_t rawstor_uuid_get_variant(struct RawstorUUID* uuid);

void rawstor_uuid_set_variant(struct RawstorUUID* uuid, uint8_t variant);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_UUID_STD_INTERNALS_H
