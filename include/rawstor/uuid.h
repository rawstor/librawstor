/**
 * Copyright (C) 2025, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_UUID_H
#define RAWSTOR_UUID_H

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


struct RawstorUUID {
    uint8_t bytes[16];
};

typedef char RawstorUUIDString[37];


int rawstor_uuid_from_string(struct RawstorUUID *uuid, const char *s);

void rawstor_uuid_to_string(
    const struct RawstorUUID *uuid, RawstorUUIDString *s);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_UUID_H
