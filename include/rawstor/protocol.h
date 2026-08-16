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
 *   0x00        session   -- every role
 *   0x01..0x1f  data      -- OST
 *   0x20..0x3f  metadata  -- shared between OST and MDS (the witness subset)
 *   0x40..0x5f  volume    -- MDS
 *
 * A server answers -ENOSYS to any opcode outside its role. The opcodes
 * below 0x20 keep the values they were released with, so a pre-0.3 peer
 * still speaks to this one.
 */
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
 * META is the per-copy mirror record (see RawstorObjectMeta); SPEC stays
 * at 7 and keeps reporting the object size only.
 */
#define RAWSTOR_CMD_META 0x20
#define RAWSTOR_CMD_SET_STATE 0x21
#define RAWSTOR_CMD_LIST_CHUNKS 0x22
/*
 * Native CoW snapshot of one stored object version (rawstor_docs/Mds.md,
 * "Snapshots"): RawstorOSTFrameBasic, val = snap_id (never 0 - 0 is the
 * live version). -ENOTSUP on backends without CoW (file://, classic LVM).
 */
#define RAWSTOR_CMD_SNAPSHOT 0x23
#define RAWSTOR_CMD_SNAP_REMOVE 0x24

#define RAWSTOR_CMD_VOL_CREATE 0x40
#define RAWSTOR_CMD_VOL_OPEN 0x41
#define RAWSTOR_CMD_VOL_RESIZE 0x42
#define RAWSTOR_CMD_VOL_REMOVE 0x43
/*
 * Volume snapshots are two-phase (rawstor_docs/Mds.md, "Snapshots"): BEGIN
 * durably reserves the snap_id (never reused - leftovers of a crashed
 * attempt must not alias a later snapshot), the client then drains, takes
 * the per-chunk CoW snapshots, and COMMIT registers exactly who holds
 * them. REMOVE unregisters first (no new readers) and returns the member
 * set for the client's fan-out destroy.
 */
#define RAWSTOR_CMD_VOL_SNAP_BEGIN 0x44
#define RAWSTOR_CMD_VOL_SNAP_COMMIT 0x45
#define RAWSTOR_CMD_VOL_SNAP_REMOVE 0x46

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
 * ALLOCATE carries the full creation spec: geometry, volume policy and
 * the placement identity the backend must record with the object.
 */
struct RawstorOSTFrameAllocateBody {
    uint8_t obj_id[16];
    uint64_t size;
    uint64_t chunk_size;
    uint64_t stripe_width;
    uint8_t width;
    uint8_t failure_domain;
    uint8_t member_kind;
    uint8_t reserved;
    uint8_t volume_id[16];
    uint64_t logical_index;
    uint64_t snap_version;
} RAWSTOR_PACKED;

struct RawstorOSTFrameAllocate {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameAllocateBody body;
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
    /*
     * Placement identity (rawstor_docs/Mds.md, chunk_meta): reported by
     * SPEC, ignored by SET_STATE (the stored values always win).
     */
    uint8_t member_kind;
    uint8_t width; /* redundancy: copies per chunk */
    uint16_t reserved;
    uint8_t volume_id[16];
    uint64_t logical_index;
    uint64_t chunk_size;
    uint64_t snap_version;
} RAWSTOR_PACKED;

/* SET_STATE request */
struct RawstorOSTFrameMeta {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameMetaBody body;
} RAWSTOR_PACKED;

/*
 * LIST_CHUNKS (rawstor_docs/Mds.md, "Reconstruct / DR") rides
 * RawstorOSTFrameBasic (obj_id/offset/val ignored). The response payload is
 * res RawstorOSTFrameMetaBody records, one per stored object, each with
 * obj_id set to the object's physical id; body.hash covers the payload.
 */

/*
 * Volume (MDS) commands — rawstor_docs/Mds.md, "Wire protocol".
 *
 * VOL_OPEN, VOL_RESIZE and VOL_REMOVE ride RawstorOSTFrameBasic
 * (obj_id = volume_id; val = snap_id for open, the new size for resize).
 */

/* Redundancy is a policy, not a wire concept: mirror in v1. */
#define RAWSTOR_VOL_REDUNDANCY_MIRROR 0

/* Failure-domain levels of the topology tree. */
#define RAWSTOR_VOL_DOMAIN_DC 0
#define RAWSTOR_VOL_DOMAIN_RACK 1
#define RAWSTOR_VOL_DOMAIN_SERVER 2
#define RAWSTOR_VOL_DOMAIN_OST 3

/* stripe_width: 1 = volume-local (DRBD-like), 0 = spread (Ceph-like). */
#define RAWSTOR_VOL_STRIPE_ALL 0

struct RawstorVolPolicy {
    uint8_t redundancy; /* RAWSTOR_VOL_REDUNDANCY_* */
    uint8_t width;      /* slots per chunk: mirror R */
    uint8_t failure_domain;
    uint8_t reserved;
    uint64_t stripe_width;
    uint64_t placement_seed;
} RAWSTOR_PACKED;

struct RawstorVolCreateBody {
    uint8_t volume_id[16]; /* client-generated, like every object id */
    uint64_t logical_size;
    uint64_t chunk_size; /* power of two */
    struct RawstorVolPolicy policy;
} RAWSTOR_PACKED;

struct RawstorVolCreate {
    struct RawstorOSTFrameHead head;
    struct RawstorVolCreateBody body;
} RAWSTOR_PACKED;

/* VOL_CREATE response payload. */
struct RawstorVolCreatedBody {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/* VOL_RESIZE response payload. */
struct RawstorVolResizedBody {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/*
 * VOL_OPEN response payload: the descriptor followed by nchunks chunk
 * entries, each entry followed by its width slots.
 */
struct RawstorVolDescriptorBody {
    uint8_t volume_id[16];
    uint64_t logical_size;
    uint64_t chunk_size;
    struct RawstorVolPolicy policy;
    uint64_t map_epoch;
    uint32_t nchunks;
} RAWSTOR_PACKED;

struct RawstorVolChunkEntry {
    uint64_t version; /* snap_id; 0 = live */
    uint8_t width;    /* slots that follow */
} RAWSTOR_PACKED;

/*
 * ost_id is the stable identity (HRW); the address is advisory routing
 * data resolved by the MDS from its topology so that clients stay
 * zero-config. A null-terminated <ip>:<port>; empty when the topology no
 * longer lists the OST (the client treats such a member as unreachable).
 */
#define RAWSTOR_VOL_ADDRESS_LEN 32

struct RawstorVolChunkSlot {
    uint8_t slot_index;
    uint8_t ost_id[16];
    char address[RAWSTOR_VOL_ADDRESS_LEN];
} RAWSTOR_PACKED;

/* VOL_SNAP_BEGIN response payload: the durably reserved snap_id. */
struct RawstorVolSnapBeganBody {
    uint64_t snap_id;
} RAWSTOR_PACKED;

/*
 * VOL_SNAP_COMMIT request: the body is followed by nmembers member
 * records - the chunk copies that actually hold the snapshot (the
 * IN-SYNC set at creation; a degraded volume snapshots with less
 * redundancy, recorded, not repaired - see Mds.md).
 *
 * VOL_SNAP_REMOVE rides RawstorOSTFrameBasic (obj_id = volume_id,
 * val = snap_id); its response payload is res member records: what was
 * registered, for the fan-out destroy.
 */
struct RawstorVolSnapCommitBody {
    uint8_t volume_id[16];
    uint64_t snap_id;
    uint32_t nmembers;
} RAWSTOR_PACKED;

struct RawstorVolSnapMemberBody {
    uint64_t logical_index;
    uint8_t ost_id[16];
} RAWSTOR_PACKED;

/* VOL_SNAP_COMMIT response payload. */
struct RawstorVolSnapCommittedBody {
    uint64_t map_epoch;
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
