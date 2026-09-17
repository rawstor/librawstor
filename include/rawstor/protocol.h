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

/*
 * One command space for every server role, grouped into reserved ranges
 * (docs/mds.md, "Wire protocol"):
 *
 *   0x00        session   -- every role
 *   0x01..0x1f  data      -- OST
 *   0x20..0x3f  metadata  -- shared between OST and MDS (the witness subset)
 *   0x40..0x5f  volume    -- MDS
 *
 * A server answers -ENOSYS to any opcode outside its role. SET_SYNC_STATE
 * (11) and META (12) predate this grouping and keep the values they were
 * released with instead of moving to their canonical 0x21/0x20 slots --
 * they already cover the "shared metadata" role those slots were reserved
 * for, so 0x20/0x21 stay unused rather than aliasing a second command onto
 * the same purpose.
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
#define RAWSTOR_CMD_WRITE_ZEROES 10
#define RAWSTOR_CMD_SET_SYNC_STATE 11
#define RAWSTOR_CMD_META 12

/*
 * 0x22 used to be LIST_CHUNKS, a dedicated one-round-trip reconstruct scan
 * command (docs/mds.md, "Reconstruct / DR"). Removed: the reconstruct scan
 * now does the same LIST + META per object the caller would otherwise do
 * itself anyway, so a separate wire command bought nothing but a second
 * code path to a result LIST+META already gets, at O(n) round trips
 * instead of one -- an acceptable cost for a scan that only runs on
 * `rawstor-mds --reconstruct`, not a hot path. Left unassigned rather than
 * reused, so an old client/server pairing fails loudly (-ENOSYS) instead
 * of silently misinterpreting a repurposed opcode.
 */
/*
 * Native CoW snapshot of one stored object version (docs/mds.md,
 * "Snapshots"): rides RawstorOSTFrameBasicPayload, val = snap_id (never 0
 * -- 0 is the live version). -ENOTSUP on backends without CoW (file://,
 * classic LVM).
 */
#define RAWSTOR_CMD_SNAPSHOT 0x23
#define RAWSTOR_CMD_SNAP_REMOVE 0x24

/*
 * Volume (MDS) commands -- docs/mds.md, "Wire protocol". VOL_OPEN,
 * VOL_RESIZE and VOL_REMOVE ride RawstorOSTFrameBasicPayload (object_id =
 * volume_id; val = snap_id for open, the new size for resize).
 */
#define RAWSTOR_CMD_VOL_CREATE 0x40
#define RAWSTOR_CMD_VOL_OPEN 0x41
#define RAWSTOR_CMD_VOL_RESIZE 0x42
#define RAWSTOR_CMD_VOL_REMOVE 0x43
/*
 * Volume snapshots are two-phase (docs/mds.md, "Snapshots"): BEGIN
 * durably reserves the snap_id (never reused -- leftovers of a crashed
 * attempt must not alias a later snapshot), the client then drains, takes
 * the per-chunk CoW snapshots, and COMMIT registers exactly who holds
 * them. REMOVE unregisters first (no new readers) and returns the member
 * set for the client's fan-out destroy.
 */
#define RAWSTOR_CMD_VOL_SNAP_BEGIN 0x44
#define RAWSTOR_CMD_VOL_SNAP_COMMIT 0x45
#define RAWSTOR_CMD_VOL_SNAP_REMOVE 0x46

typedef uint16_t RawstorOSTCommandType;

// Wire representation of enum RawstorObjectSyncStateValue
// (<rawstor/target.h>, values RAWSTOR_OBJECT_SYNC_STATE_*) -- a fixed-width
// typedef rather than the enum itself, same reasoning as
// RawstorOSTCommandType above: an enum's underlying type isn't guaranteed
// portable across compilers, which a RAWSTOR_PACKED wire struct can't risk.
// uint8_t is plenty for a 3-value state (same size class as
// RawstorOSTFrameIOPayload::flags below).
typedef uint8_t RawstorOSTSyncStateType;

struct RawstorOSTFrameHead {
    uint32_t magic;
    RawstorOSTCommandType cmd;
    uint16_t cid;
} RAWSTOR_PACKED;

/* request frames */

/* Minimalistic protocol frame */
struct RawstorOSTFrameBasicPayload {
    // var is for minimal commands only,
    // will be overridden in other command structs
    uint8_t object_id[16];
    uint64_t offset;
    uint64_t val;
} RAWSTOR_PACKED;

struct RawstorOSTFrameBasic {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameBasicPayload payload;
} RAWSTOR_PACKED;

// Shared by READ/WRITE/DISCARD/WRITE_ZEROES: `hash` is only meaningful for
// WRITE (payload integrity check) and READ (of its response body) --
// DISCARD/WRITE_ZEROES carry no payload, so it's unused there (send as 0,
// ignore on receipt). `flags` is a RAWSTOR_FLAG_* bitmask, shared across
// every command that uses it: WRITE sets only RAWSTOR_FLAG_SYNC,
// WRITE_ZEROES sets RAWSTOR_FLAG_SYNC and/or RAWSTOR_FLAG_UNMAP, and
// DISCARD leaves the byte unused (0).
struct RawstorOSTFrameIOPayload {
    uint64_t offset;
    uint32_t len;
    uint64_t hash;
    uint8_t flags;
} RAWSTOR_PACKED;

// RawstorOSTFrameIOPayload::flags bits above: whether the affected range
// must be durable before the response is sent (same meaning as
// rawstor_object_pwrite()'s own `sync`; meaningful for WRITE and
// WRITE_ZEROES), and, for WRITE_ZEROES only, whether the backend may
// deallocate the zeroed range's storage (same meaning as virtio-blk's
// VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP).
#define RAWSTOR_FLAG_SYNC (1u << 0)
#define RAWSTOR_FLAG_UNMAP (1u << 1)

struct RawstorOSTFrameIO {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameIOPayload payload;
} RAWSTOR_PACKED;

/*
 * Settable mirror consistency state only -- no size, nothing here changes
 * it. SET_SYNC_STATE's request: unlike SPEC/META, it isn't wrapped in a
 * RawstorOSTFrameBasicPayload of its own, so object_id here is the only way the
 * server learns which object this applies to.
 */
struct RawstorOSTFrameSyncStatePayload {
    uint8_t object_id[16];
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    RawstorOSTSyncStateType state;
} RAWSTOR_PACKED;

/* SET_SYNC_STATE request */
struct RawstorOSTFrameSyncState {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameSyncStatePayload payload;
} RAWSTOR_PACKED;

/*
 * ALLOCATE's request: the object to create's size and mirrors. Unlike
 * SPEC's response (RawstorOSTFrameSpecPayload below), this does need
 * object_id -- it isn't wrapped in a RawstorOSTFrameBasicPayload of its
 * own, so object_id here is the only way the server learns which object
 * to create.
 *
 * The fields below `mirrors` are the chunk placement identity
 * (docs/mds.md, chunk_meta): stamped at create by the volume
 * layer, immutable afterwards, the source (via META) for the reconstruct
 * scan. An all-zero volume_id is a standalone object -- the
 * degenerate case a plain mirrored object already is today, `mirrors`
 * doubling as `width` (copies per chunk).
 */
struct RawstorOSTFrameAllocatePayload {
    uint8_t object_id[16];
    uint64_t size;
    uint32_t mirrors;
    uint64_t chunk_size;    /* power of two; 0 = one chunk spans the volume */
    uint64_t stripe_width;  /* K; 0 = spread every chunk, 1 = volume-local */
    uint8_t failure_domain; /* RAWSTOR_VOL_DOMAIN_* */
    uint8_t member_kind;    /* enum RawstorMemberKind, <rawstor/target.h> */
    uint16_t reserved;
    uint8_t volume_id[16];  /* parent volume; all-zero = standalone */
    uint64_t logical_index; /* chunk position within the volume */
    uint64_t snap_id; /* snapshot version this copy belongs to; 0 = live */
} RAWSTOR_PACKED;

/* ALLOCATE request */
struct RawstorOSTFrameAllocate {
    struct RawstorOSTFrameHead head;
    struct RawstorOSTFrameAllocatePayload payload;
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
 * Full per-copy metadata: size plus the mirror consistency state (see
 * docs/mirroring.md). sync_id_history length must match
 * RAWSTOR_OBJECT_SYNC_ID_HISTORY. META response payload only -- SPEC's is
 * RawstorOSTFrameSpecPayload (size + mirrors, cheaper), SET_SYNC_STATE's
 * request is RawstorOSTFrameSyncStatePayload (settable fields only, no
 * size). No object_id: this is only ever a response, correlated to its
 * request via RawstorOSTFrameHead::cid -- the caller already knows which
 * object it asked about. Sent as a RawstorOSTFrameResponse (body.res =
 * sizeof(this), body.hash covering it) immediately followed by this
 * payload -- no combined frame struct, since every actual sender/receiver
 * already handles header and payload as two separate pieces (a fixed-size
 * header read, then a body.res-sized payload read, or a two-part iovec
 * write).
 */
struct RawstorOSTFrameMetaPayload {
    uint64_t size;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    RawstorOSTSyncStateType state;
    /*
     * Placement identity (docs/mds.md, chunk_meta): reported by
     * META, ignored by SET_SYNC_STATE (the stored values always win).
     */
    uint8_t member_kind; /* enum RawstorMemberKind, <rawstor/target.h> */
    uint8_t width;       /* redundancy: copies per chunk */
    uint16_t reserved;
    uint8_t volume_id[16];
    uint64_t logical_index;
    uint64_t chunk_size;
    uint64_t snap_id;
} RAWSTOR_PACKED;

/*
 * SPEC's response: an object's size and mirrors, cheaper than META's since
 * it carries no consistency state. No object_id, same reasoning as
 * RawstorOSTFrameMetaPayload above -- correlated via
 * RawstorOSTFrameHead::cid, the caller already knows which object it asked
 * about. Sent as a RawstorOSTFrameResponse (body.res = sizeof(this),
 * body.hash covering it) immediately followed by this payload -- no
 * combined response frame struct, since every actual sender/receiver
 * already handles header and payload as two separate pieces (a fixed-size
 * header read, then a body.res-sized payload read, or a two-part iovec
 * write).
 */
struct RawstorOSTFrameSpecPayload {
    uint64_t size;
    uint32_t mirrors;
} RAWSTOR_PACKED;

/*
 * Volume (MDS) wire structs -- docs/mds.md, "Wire protocol" /
 * "MDS data model". VOL_OPEN, VOL_RESIZE and VOL_REMOVE ride
 * RawstorOSTFrameBasicPayload (object_id = volume_id; val = snap_id for
 * open, the new size for resize) and need no struct of their own.
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

struct RawstorVolCreatePayload {
    uint8_t volume_id[16]; /* client-generated, like every object id */
    uint64_t logical_size;
    uint64_t chunk_size; /* power of two */
    struct RawstorVolPolicy policy;
} RAWSTOR_PACKED;

struct RawstorVolCreate {
    struct RawstorOSTFrameHead head;
    struct RawstorVolCreatePayload payload;
} RAWSTOR_PACKED;

/* VOL_CREATE response payload. */
struct RawstorVolCreatedPayload {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/* VOL_RESIZE response payload. */
struct RawstorVolResizedPayload {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/*
 * VOL_OPEN response payload: the descriptor followed by nchunks chunk
 * entries, each entry followed by its width slots (RawstorVolChunkEntry,
 * then that many RawstorVolChunkSlot records).
 */
struct RawstorVolDescriptorPayload {
    uint8_t volume_id[16];
    uint64_t logical_size;
    uint64_t chunk_size;
    struct RawstorVolPolicy policy;
    uint64_t map_epoch;
    uint32_t nchunks;
} RAWSTOR_PACKED;

struct RawstorVolChunkEntry {
    uint64_t snap_id; /* 0 = live */
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
struct RawstorVolSnapBeganPayload {
    uint64_t snap_id;
} RAWSTOR_PACKED;

/*
 * VOL_SNAP_COMMIT request: the payload is followed by nmembers member
 * records -- the chunk copies that actually hold the snapshot (the
 * IN-SYNC set at creation; a degraded volume snapshots with less
 * redundancy, recorded, not repaired -- see Mds.md).
 *
 * VOL_SNAP_REMOVE rides RawstorOSTFrameBasicPayload (object_id =
 * volume_id, val = snap_id); its response payload is `res`
 * RawstorVolSnapMemberPayload records: what was registered, for the
 * fan-out destroy.
 */
struct RawstorVolSnapCommitPayload {
    uint8_t volume_id[16];
    uint64_t snap_id;
    uint32_t nmembers;
} RAWSTOR_PACKED;

struct RawstorVolSnapMemberPayload {
    uint64_t logical_index;
    uint8_t ost_id[16];
} RAWSTOR_PACKED;

/* VOL_SNAP_COMMIT response payload. */
struct RawstorVolSnapCommittedPayload {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PROTOCOL_H
