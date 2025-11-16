/**
 * Copyright (C) 2025, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1
 * of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
