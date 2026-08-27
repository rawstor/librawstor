/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_PROTOCOL_H
#define RAWSTOR_PROTOCOL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAWSTOR_PACKED __attribute__((packed))

#define RAWSTOR_MAGIC 0x72737472 // "rstr" as ascii

#define RAWSTOR_CMD_SET_OBJECT 0
#define RAWSTOR_CMD_READ 1
#define RAWSTOR_CMD_WRITE 2
#define RAWSTOR_CMD_DISCARD 3
#define RAWSTOR_CMD_ALLOCATE 4
#define RAWSTOR_CMD_RELEASE 5
#define RAWSTOR_CMD_LIST 6
#define RAWSTOR_CMD_SPEC 7
#define RAWSTOR_CMD_LOCATION_INFO 8
#define RAWSTOR_CMD_FLUSH 9
#define RAWSTOR_CMD_WRITE_ZEROES 10
typedef uint16_t RawstorOSTCommandType;

struct RawstorOSTFrameHead {
    uint32_t magic;
    RawstorOSTCommandType cmd;
    uint16_t cid;
} RAWSTOR_PACKED;

/* Minimalistic protocol frame */
struct RawstorOSTFrameBasicBody {
    // var is for minimal commands only,
    // will be overridden in other command structs
    uint8_t obj_id[16];
    uint64_t offset;
    uint64_t val;
} RAWSTOR_PACKED;

struct RawstorOSTFrameBasic {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameBasicBody body;
} RAWSTOR_PACKED;

// Shared by READ/WRITE/DISCARD/WRITE_ZEROES: `hash` is only meaningful for
// WRITE (payload integrity check) and READ (of its response body) --
// DISCARD/WRITE_ZEROES carry no payload, so it's unused there (send as 0,
// ignore on receipt). For WRITE, `sync` is the single durability flag (0
// or 1). WRITE_ZEROES instead reads the same byte as a bitmask of
// RAWSTOR_WRITE_ZEROES_FLAG_*, since it needs both an unmap hint and its
// own durability flag; DISCARD leaves the byte unused (0).
struct RawstorOSTFrameIOBody {
    uint64_t offset;
    uint32_t len;
    uint64_t hash;
    uint8_t sync;
} RAWSTOR_PACKED;

// WRITE_ZEROES's flags, packed into RawstorOSTFrameIOBody::sync above: may
// the backend deallocate the zeroed range's storage (same meaning as
// virtio-blk's VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP), and whether the range
// must be durable before the response is sent (same meaning as WRITE's own
// `sync`).
#define RAWSTOR_WRITE_ZEROES_FLAG_UNMAP (1u << 0)
#define RAWSTOR_WRITE_ZEROES_FLAG_SYNC (1u << 1)

struct RawstorOSTFrameIO {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameIOBody body;
} RAWSTOR_PACKED;

/* response frames */
struct RawstorOSTFrameResponseBody {
    // TODO: if we send length in res - it should be the same type
    // (signed-unsigned too)
    int32_t res;
    uint64_t hash;
} RAWSTOR_PACKED;

struct RawstorOSTFrameResponse {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameResponseBody body;
} RAWSTOR_PACKED;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PROTOCOL_H
