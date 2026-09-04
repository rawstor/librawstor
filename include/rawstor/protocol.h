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
#define RAWSTOR_CMD_SET_SYNC_STATE 11
#define RAWSTOR_CMD_META 12
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
// ignore on receipt). `flags` is a RAWSTOR_FLAG_* bitmask, shared across
// every command that uses it: WRITE sets only RAWSTOR_FLAG_SYNC,
// WRITE_ZEROES sets RAWSTOR_FLAG_SYNC and/or RAWSTOR_FLAG_UNMAP, and
// DISCARD leaves the byte unused (0).
struct RawstorOSTFrameIOBody {
    uint64_t offset;
    uint32_t len;
    uint64_t hash;
    uint8_t flags;
} RAWSTOR_PACKED;

// RawstorOSTFrameIOBody::flags bits above: whether the affected range must
// be durable before the response is sent (same meaning as
// rawstor_object_pwrite()'s own `sync`; meaningful for WRITE and
// WRITE_ZEROES), and, for WRITE_ZEROES only, whether the backend may
// deallocate the zeroed range's storage (same meaning as virtio-blk's
// VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP).
#define RAWSTOR_FLAG_SYNC (1u << 0)
#define RAWSTOR_FLAG_UNMAP (1u << 1)

struct RawstorOSTFrameIO {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameIOBody body;
} RAWSTOR_PACKED;

/*
 * Full per-copy metadata: size plus the mirror consistency state (see
 * docs/mirroring.md). sync_id_history length must match
 * RAWSTOR_OBJECT_SYNC_ID_HISTORY. META response payload only -- SPEC's is
 * RawstorOSTFrameSpecPayload (size only, cheaper), SET_SYNC_STATE's request is
 * RawstorOSTFrameSyncStateBody (settable fields only, no size). No obj_id:
 * unlike RawstorOSTFrameSyncStateBody below, this is only ever a response,
 * correlated to its request via RawstorOSTFrameHead::cid -- the caller
 * already knows which object it asked about. Sent as a RawstorOSTFrameResponse
 * (body.res = sizeof(this), body.hash covering it) immediately followed by
 * this payload -- no combined frame struct, since every actual sender/
 * receiver already handles header and payload as two separate pieces (a
 * fixed-size header read, then a body.res-sized payload read, or a two-part
 * iovec write).
 */
struct RawstorOSTFrameMetaPayload {
    uint64_t size;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    uint32_t state;
} RAWSTOR_PACKED;

/*
 * Settable mirror consistency state only -- no size, nothing here changes
 * it. SET_SYNC_STATE's request: unlike SPEC/META, it isn't wrapped in a
 * RawstorOSTFrameBasicBody of its own, so obj_id here is the only way the
 * server learns which object this applies to.
 */
struct RawstorOSTFrameSyncStateBody {
    uint8_t obj_id[16];
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    uint32_t state;
} RAWSTOR_PACKED;

/* SET_SYNC_STATE request */
struct RawstorOSTFrameSyncState {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameSyncStateBody body;
} RAWSTOR_PACKED;

/* response frames */
struct RawstorOSTFrameResponseBody {
    uint64_t hash;
    // TODO: if we send length in res - it should be the same type
    // (signed-unsigned too)
    int32_t res;
} RAWSTOR_PACKED;

struct RawstorOSTFrameResponse {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameResponseBody body;
} RAWSTOR_PACKED;

/*
 * Just the object's size -- SPEC response payload, cheaper than META's. No
 * obj_id, same reasoning as RawstorOSTFrameMetaPayload above. Sent as a
 * RawstorOSTFrameResponse (body.res = sizeof(this), body.hash covering it)
 * immediately followed by this payload -- no combined frame struct, since
 * every actual sender/receiver already handles header and payload as two
 * separate pieces (a fixed-size header read, then a body.res-sized payload
 * read, or a two-part iovec write).
 */
struct RawstorOSTFrameSpecPayload {
    uint64_t size;
} RAWSTOR_PACKED;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PROTOCOL_H
