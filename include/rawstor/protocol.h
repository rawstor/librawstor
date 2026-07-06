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

#define RAWSTOR_PROTOCOL_VERSION 1u

/*
 * One command space for every server role, grouped into reserved ranges
 * (rawstor_docs/Mds.md, "Wire protocol"):
 *
 *   0x00        session   — every role
 *   0x01..0x1f  data      — OST
 *   0x20..0x3f  metadata  — shared between OST and MDS (the witness subset)
 *   0x40..0x5f  volume    — MDS
 *
 * A server answers -ENOSYS to any opcode outside its role.
 */
#define RAWSTOR_CMD_SET_OBJECT 0x00

#define RAWSTOR_CMD_READ 0x01
#define RAWSTOR_CMD_WRITE 0x02
#define RAWSTOR_CMD_DISCARD 0x03
#define RAWSTOR_CMD_ALLOCATE 0x04
#define RAWSTOR_CMD_RELEASE 0x05
#define RAWSTOR_CMD_FLUSH 0x06

#define RAWSTOR_CMD_SPEC 0x20
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

/*
 * SET_OBJECT doubles as the connection handshake: it must be the first
 * command on every connection and carries the protocol version and feature
 * bits. An all-zero obj_id is a control connection: no object is bound
 * (volume/metadata commands only).
 */
struct RawstorOSTFrameSetObjectBody {
    uint32_t version;  /* RAWSTOR_PROTOCOL_VERSION */
    uint64_t features; /* feature bits; none defined yet */
    uint8_t obj_id[16];
    uint64_t val; /* reserved (snap_id); 0 = live */
} RAWSTOR_PACKED;

struct RawstorOSTFrameSetObject {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameSetObjectBody body;
} RAWSTOR_PACKED;

/* SET_OBJECT response payload: the server side of the handshake. */
struct RawstorOSTFrameHelloBody {
    uint32_t version;
    uint64_t features;
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

/*
 * Response frame, one shape for every command: res is the operation
 * result (>= 0 ok, < 0 -errno), len is the length of the payload that
 * follows, hash covers that payload (0 when len == 0). Error responses
 * carry no payload (len == 0).
 */
struct RawstorOSTFrameResponseBody {
    int32_t res;
    uint32_t len;
    uint64_t hash;
} RAWSTOR_PACKED;

struct RawstorOSTFrameResponse {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameResponseBody body;
} RAWSTOR_PACKED;

/*
 * SPEC response: standard response followed by the object metadata.
 * body.hash covers the meta payload.
 */
struct RawstorOSTFrameSpecResponse {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameResponseBody body;
    struct RawstorOSTFrameMetaBody meta;
} RAWSTOR_PACKED;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PROTOCOL_H
