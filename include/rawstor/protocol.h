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

/*
 * Metadata-plane commands live at 0x20 and up, leaving room for the
 * object I/O commands above to keep growing contiguously. META is the
 * per-copy mirror record (see RawstorObjectMeta); SPEC stays at 7 and
 * keeps reporting the object size only, so pre-0.3 peers are unaffected.
 */
#define RAWSTOR_CMD_META 0x20
#define RAWSTOR_CMD_SET_STATE 0x21
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

struct RawstorOSTFrameIOBody {
    uint64_t offset;
    uint32_t len;
    uint64_t hash;
    uint8_t sync;
} RAWSTOR_PACKED;

struct RawstorOSTFrameIO {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameIOBody body;
} RAWSTOR_PACKED;

/*
 * Object metadata: mirror consistency state (see docs/mirroring.md).
 * sync_id_history length must match RAWSTOR_OBJECT_SYNC_ID_HISTORY.
 */
struct RawstorOSTFrameMetaBody {
    uint8_t obj_id[16];
    uint64_t size;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    uint32_t state;
} RAWSTOR_PACKED;

/* SET_STATE request */
struct RawstorOSTFrameMeta {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameMetaBody body;
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

/*
 * META response: standard response followed by the object metadata.
 * body.hash covers the meta payload.
 */
struct RawstorOSTFrameMetaResponse {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameResponseBody body;
    struct RawstorOSTFrameMetaBody meta;
} RAWSTOR_PACKED;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PROTOCOL_H
