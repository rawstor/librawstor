#ifndef RAWSTD_UUID_STD_INTERNALS_H
#define RAWSTD_UUID_STD_INTERNALS_H

#include "rawstd/uuid.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rawstd_uuid7_get_timestamp(const struct RawstdUUID* uuid);

int rawstd_uuid7_set_timestamp(struct RawstdUUID* uuid, uint64_t ts);

uint64_t rawstd_uuid7_get_counter(const struct RawstdUUID* uuid);

int rawstd_uuid7_set_counter(struct RawstdUUID* uuid, uint64_t counter);

uint8_t rawstd_uuid_get_version(struct RawstdUUID* uuid);

void rawstd_uuid_set_version(struct RawstdUUID* uuid, uint8_t version);

uint8_t rawstd_uuid_get_variant(struct RawstdUUID* uuid);

void rawstd_uuid_set_variant(struct RawstdUUID* uuid, uint8_t variant);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_UUID_STD_INTERNALS_H
