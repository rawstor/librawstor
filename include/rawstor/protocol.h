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
 *   0x40..0x5f  object    -- MDS
 *
 * A server answers -ENOSYS to any opcode outside its role. SET_SYNC_STATE
 * (0x0b) and META (0x0c) predate this grouping and keep the values they were
 * released with instead of moving to their canonical 0x21/0x20 slots --
 * they already cover the "shared metadata" role those slots were reserved
 * for, so 0x20/0x21 stay unused rather than aliasing a second command onto
 * the same purpose.
 *
 * Every wire struct is named after the protocol, not a server role:
 * RawstorFrame* for frames and payloads any role may use, and
 * RawstorFrameObj* for the payloads of the object (RAWSTOR_CMD_OBJ_*)
 * commands.
 */
#define RAWSTOR_CMD_SET_OBJECT 0x00
#define RAWSTOR_CMD_READ 0x01
#define RAWSTOR_CMD_WRITE 0x02
#define RAWSTOR_CMD_DISCARD 0x03
#define RAWSTOR_CMD_ALLOCATE 0x04
/*
 * Removes an object/chunk -- or, if `snapshot_id` is non-nil, one previously
 * snapshotted version of it instead (nil-means-live, same convention as
 * SET_OBJECT/OBJ_OPEN) -- rides RawstorFrameBasicPayload.
 */
#define RAWSTOR_CMD_RELEASE 0x05
#define RAWSTOR_CMD_LIST 0x06
#define RAWSTOR_CMD_LOCATION_INFO 0x08
#define RAWSTOR_CMD_FLUSH 0x09
#define RAWSTOR_CMD_WRITE_ZEROES 0x0a
#define RAWSTOR_CMD_SET_SYNC_STATE 0x0b
#define RAWSTOR_CMD_META 0x0c
/*
 * Native CoW snapshot of one stored object version (docs/mds.md,
 * "Snapshots"): rides RawstorFrameBasicPayload, snapshot_id is the
 * caller's own already-generated version id (like every object id,
 * client-generated -- never nil, nil is reserved for the live version).
 * -ENOTSUP on backends without CoW (file://, classic LVM).
 */
#define RAWSTOR_CMD_SNAPSHOT 0x0d

/*
 * Object (MDS) commands -- docs/mds.md, "Wire protocol": create/open/
 * resize/remove a whole, possibly multi-chunk mds:// object. OBJ_OPEN,
 * OBJ_RESIZE and OBJ_REMOVE all ride RawstorFrameBasicPayload
 * (object_id = id; val = the new size for resize, unused for open/
 * remove; snapshot_id = the bound version for open, nil = live, unused
 * for resize/remove).
 */
#define RAWSTOR_CMD_OBJ_CREATE 0x40
#define RAWSTOR_CMD_OBJ_OPEN 0x41
#define RAWSTOR_CMD_OBJ_RESIZE 0x42
#define RAWSTOR_CMD_OBJ_REMOVE 0x43
/*
 * Object snapshots (docs/mds.md, "Snapshots"): the client generates
 * snapshot_id itself, like every object id, before taking any per-chunk CoW
 * copy -- COMMIT registers exactly who ends up holding them once every
 * reachable chunk has one (rides RawstorFrameObjSnapCommitPayload). REMOVE
 * unregisters first (no new readers) and returns the member set for the
 * client's fan-out destroy (rides RawstorFrameBasicPayload: object_id =
 * id, snapshot_id = the version to remove).
 */
#define RAWSTOR_CMD_OBJ_SNAP_COMMIT 0x45
#define RAWSTOR_CMD_OBJ_SNAP_REMOVE 0x46

typedef uint16_t RawstorCommandType;

// Wire representation of enum RawstorObjectSyncStateValue
// (<rawstor/target.h>, values RAWSTOR_OBJECT_SYNC_STATE_*) -- a fixed-width
// typedef rather than the enum itself, same reasoning as
// RawstorCommandType above: an enum's underlying type isn't guaranteed
// portable across compilers, which a RAWSTOR_PACKED wire struct can't risk.
// uint8_t is plenty for a 3-value state (same size class as
// RawstorFrameIOPayload::flags below).
typedef uint8_t RawstorSyncStateType;

struct RawstorFrameHead {
    uint32_t magic;
    RawstorCommandType cmd;
    uint16_t cid;
} RAWSTOR_PACKED;

/* request frames */

/*
 * Minimalistic protocol frame, shared by every command that doesn't need
 * one of the bigger, dedicated payloads elsewhere (READ/WRITE/DISCARD/
 * WRITE_ZEROES, SET_SYNC_STATE, ALLOCATE, LIST). `offset` is the
 * chunk_offset of the object/chunk `object_id` names (0 for a plain,
 * non-chunked object) for META; unused (0) for LOCATION_INFO/FLUSH.
 * `snapshot_id` binds to a previously snapshotted version instead of the
 * live one, for the handful of commands that use it (SET_OBJECT, RELEASE,
 * SNAPSHOT, OBJ_OPEN, OBJ_SNAP_REMOVE -- each command's own doc comment
 * above says which; nil means "the live version" where that's a
 * meaningful state for the command, SET_OBJECT/RELEASE/OBJ_OPEN, while
 * SNAPSHOT/OBJ_SNAP_REMOVE always carry a real, non-nil version); left
 * nil (unused) by every other command. `val` is command-specific (e.g.
 * the new size for OBJ_RESIZE, the open flags -- RAWSTOR_READONLY,
 * <rawstor/target.h>, or 0 -- for SET_OBJECT, which a bound snapshot
 * always carries); unused (0) for RELEASE/SNAPSHOT/OBJ_OPEN/
 * OBJ_SNAP_REMOVE. `snapshot_id` and `val` are otherwise never both
 * meaningful on the same command (SET_OBJECT is the one exception), but
 * living in one struct means
 * every command that carries object_id/offset shares one wire shape and
 * one C++-side request path (Backend::_basic_request(), ost_backend.cpp)
 * instead of two nearly identical ones.
 */
struct RawstorFrameBasicPayload {
    uint8_t object_id[16];
    uint64_t offset;
    uint8_t snapshot_id[16];
    uint64_t val;
} RAWSTOR_PACKED;

struct RawstorFrameBasic {
    struct RawstorFrameHead head;
    struct RawstorFrameBasicPayload payload;
} RAWSTOR_PACKED;

/*
 * LIST's request: `token_id` resumes strictly after the id it names --
 * every offset a listed id has is always reported together in the same
 * page (rawstor::Backend::list_chunks()'s own contract, src/backend.hpp:
 * one page entry is an id plus every offset it has, never split across
 * pages), so resuming only ever needs to name an id, unlike
 * RawstorFrameBasicPayload's own offset/snapshot_id fields, which
 * LIST has no use for. This is why LIST gets its own dedicated request
 * payload rather than reusing that one; its own response shape
 * (BackendOpBasic's plain array-of-T, ost_backend.cpp) doesn't fit LIST's
 * own resume-cursor-as-last-entry convention either (RawstorFrameList
 * Entry's own doc comment below). A nil token_id means "from the start",
 * matching a nil RawstdUUID.
 */
struct RawstorFrameListPayload {
    uint8_t token_id[16];
    uint32_t limit;
} RAWSTOR_PACKED;

struct RawstorFrameList {
    struct RawstorFrameHead head;
    struct RawstorFrameListPayload payload;
} RAWSTOR_PACKED;

/*
 * One LIST response row: one id's own one offset -- a listed id with
 * more than one offset (distinct chunks of the same multi-chunk object)
 * rides one row per offset, all sharing that id, which the receiving end
 * groups back into one rawstor::ChunkGroup (src/backend.hpp) per id.
 * Only live objects are listed. The response body is a packed array of these
 * (body.res = count * sizeof(this)), same "array of T" shape
 * RawstorFrameBasic's own response (e.g. an older LIST) used, with one
 * addition: the *last* row is always the resume cursor for the next page
 * (a nil id once nothing is left), never a real result -- the serving
 * rawstor-ost may itself be relaying across more than one local location,
 * whose own merged resume point isn't necessarily identical to the last
 * real row returned (see rawstor::Location::list()'s own doc comment).
 * An empty response body (no rows at all, not even a cursor) means the
 * far end is already exhausted.
 */
struct RawstorFrameListEntry {
    uint8_t id[16];
    uint64_t chunk_offset;
} RAWSTOR_PACKED;

// Shared by READ/WRITE/DISCARD/WRITE_ZEROES: `hash` is only meaningful for
// WRITE (payload integrity check) and READ (of its response body) --
// DISCARD/WRITE_ZEROES carry no payload, so it's unused there (send as 0,
// ignore on receipt). `flags` is a RAWSTOR_FLAG_* bitmask, shared across
// every command that uses it: WRITE sets only RAWSTOR_FLAG_SYNC,
// WRITE_ZEROES sets RAWSTOR_FLAG_SYNC and/or RAWSTOR_FLAG_UNMAP, and
// DISCARD leaves the byte unused (0).
struct RawstorFrameIOPayload {
    uint64_t offset;
    uint64_t hash;
    uint32_t len;
    uint8_t flags;
} RAWSTOR_PACKED;

// RawstorFrameIOPayload::flags bits above: whether the affected range
// must be durable before the response is sent (same meaning as
// rawstor_object_pwrite()'s own `sync`; meaningful for WRITE and
// WRITE_ZEROES), and, for WRITE_ZEROES only, whether the backend may
// deallocate the zeroed range's storage (same meaning as virtio-blk's
// VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP).
#define RAWSTOR_FLAG_SYNC (1u << 0)
#define RAWSTOR_FLAG_UNMAP (1u << 1)

struct RawstorFrameIO {
    struct RawstorFrameHead head;
    struct RawstorFrameIOPayload payload;
} RAWSTOR_PACKED;

/*
 * Settable mirror consistency state only -- no size, nothing here changes
 * it. SET_SYNC_STATE's request: unlike META, it isn't wrapped in a
 * RawstorFrameBasicPayload of its own, so object_id/chunk_offset here
 * are the only way the server learns which object (and which of its
 * chunks -- docs/mds.md, "Chunk identity") this applies to.
 */
struct RawstorFrameSyncStatePayload {
    uint8_t object_id[16];
    uint64_t chunk_offset;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    RawstorSyncStateType state;
} RAWSTOR_PACKED;

/* SET_SYNC_STATE request */
struct RawstorFrameSyncState {
    struct RawstorFrameHead head;
    struct RawstorFrameSyncStatePayload payload;
} RAWSTOR_PACKED;

/*
 * ALLOCATE's request: the object to create's size and width. Unlike
 * META's response (RawstorFrameMetaPayload below), this does need
 * object_id -- it isn't wrapped in a RawstorFrameBasicPayload of its
 * own, so object_id/chunk_offset here are the only way the server learns
 * which object (and which of its chunks) to create.
 *
 * chunk_shift/stripe_width/failure_domain/member_role are the chunk's own
 * placement policy (docs/mds.md, chunk_meta): stamped at create by the
 * volume layer, immutable afterwards. chunk_shift carries chunk_size's
 * (RawstorObjectSpec.chunk_size, target.h) own log2 rather than the full
 * value -- Target::create() already rejects a non-power-of-two chunk_size
 * before it ever reaches the wire, so a shift always round-trips exactly,
 * and it's cheaper on the wire besides; 0 means no chunking, same meaning
 * as chunk_size == 0. Unlike an earlier version of this payload, no
 * volume_id/logical_index/snapshot_id fields are carried here any more --
 * object_id already *is* the volume's own id for every one of its chunks
 * (docs/mds.md, "Chunk identity": obj_id = volume_id), chunk_offset
 * disambiguates which chunk, and this backend's own snapshot_id is always 0
 * at create time (RAWSTOR_CMD_SNAPSHOT registers one afterwards) -- see
 * RawstorObjectSpec's own doc comment in target.h.
 */
struct RawstorFrameAllocatePayload {
    uint8_t object_id[16];
    uint64_t chunk_offset;
    uint64_t size;
    uint64_t stripe_width; /* K; 0 = spread every chunk, 1 = object-local */
    uint8_t chunk_shift;
    uint8_t failure_domain; /* RAWSTOR_OBJ_DOMAIN_* */
    uint8_t width;          /* redundancy: copies per chunk */
    uint8_t member_role;    /* enum RawstorMemberRole, <rawstor/target.h> */
    uint32_t reserved2;
} RAWSTOR_PACKED;

/* ALLOCATE request */
struct RawstorFrameAllocate {
    struct RawstorFrameHead head;
    struct RawstorFrameAllocatePayload payload;
} RAWSTOR_PACKED;

/* response frames */
struct RawstorFrameResponseBody {
    uint64_t hash;
    // TODO: if we send length in res - it should be the same type
    // (signed-unsigned too)
    int32_t res;
} RAWSTOR_PACKED;

struct RawstorFrameResponse {
    struct RawstorFrameHead head;
    struct RawstorFrameResponseBody body;
} RAWSTOR_PACKED;

/*
 * Full per-copy metadata: size, chunk_shift (RawstorFrameAllocate-
 * Payload's own doc comment on why a shift, not the full chunk_size) and
 * the mirror consistency state (see docs/mirroring.md) -- RawstorObjectMeta
 * (target.h) is spec plus sync_state, so this is the one wire round trip
 * that reports everything a caller could want about one copy. sync_id_history
 * length must match RAWSTOR_OBJECT_SYNC_ID_HISTORY. The only per-copy
 * response payload -- SET_SYNC_STATE's request is RawstorFrameSyncState-
 * Payload (settable fields only, no size). No object_id: this is only
 * ever a response, correlated to its request via RawstorFrameHead::cid
 * -- the caller already knows which object it asked about. Sent as a
 * RawstorFrameResponse (body.res = sizeof(this), body.hash covering
 * it) immediately followed by this payload -- no combined frame struct,
 * since every actual sender/receiver already handles header and payload
 * as two separate pieces (a fixed-size header read, then a body.res-sized
 * payload read, or a two-part iovec write).
 */
struct RawstorFrameMetaPayload {
    uint64_t size;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[4];
    RawstorSyncStateType state;
    uint8_t chunk_shift;
    /*
     * Rest of the placement identity (docs/mds.md, chunk_meta): reported
     * by META, ignored by SET_SYNC_STATE (the stored values always win).
     */
    uint8_t width;       /* redundancy: copies per chunk */
    uint8_t member_role; /* enum RawstorMemberRole, <rawstor/target.h> */
    uint32_t reserved2;
} RAWSTOR_PACKED;

/*
 * Object (MDS) wire structs -- docs/mds.md, "Wire protocol" /
 * "MDS data model": a whole, possibly multi-chunk mds:// object. OBJ_OPEN,
 * OBJ_RESIZE and OBJ_REMOVE ride RawstorFrameBasicPayload (object_id =
 * id; val = snapshot_id for open, the new size for resize) and need no
 * struct of their own.
 */

/* Redundancy is a policy, not a wire concept: mirror in v1. */
#define RAWSTOR_OBJ_REDUNDANCY_MIRROR 0

/*
 * Failure-domain levels of the topology tree, numbered from the leaf up so
 * a wider level (e.g. a region above dc) only ever takes the next number.
 * 0 is "not set": the client resolves it to its default (server) before
 * anything reaches the MDS or is stored.
 */
#define RAWSTOR_OBJ_DOMAIN_DEFAULT 0
#define RAWSTOR_OBJ_DOMAIN_OST 1
#define RAWSTOR_OBJ_DOMAIN_SERVER 2
#define RAWSTOR_OBJ_DOMAIN_RACK 3
#define RAWSTOR_OBJ_DOMAIN_ROW 4
#define RAWSTOR_OBJ_DOMAIN_DC 5

/* stripe_width: 1 = object-local (DRBD-like), 0 = spread (Ceph-like). */
#define RAWSTOR_OBJ_STRIPE_ALL 0

/*
 * The 64-bit fields lead, so they stay 8-byte aligned wherever this is
 * embedded at an 8-byte offset (RawstorFrameObjCreatePayload,
 * RawstorFrameObjDescriptorPayload); `reserved` rounds it to 4 bytes past
 * them, so a 32-bit field right after it stays aligned too.
 */
struct RawstorFrameObjPolicy {
    uint64_t stripe_width;
    uint64_t placement_seed;
    uint8_t redundancy; /* RAWSTOR_OBJ_REDUNDANCY_* */
    uint8_t width;      /* slots per chunk: mirror R */
    uint8_t failure_domain;
    uint8_t reserved;
} RAWSTOR_PACKED;

/*
 * chunk_shift is log2(chunk_size), like RawstorFrameAllocatePayload's:
 * an mds:// object's chunk_size is always a nonzero power of two.
 */
struct RawstorFrameObjCreatePayload {
    uint8_t id[16]; /* client-generated, like every object id */
    uint64_t logical_size;
    struct RawstorFrameObjPolicy policy;
    uint8_t chunk_shift;
} RAWSTOR_PACKED;

struct RawstorFrameObjCreate {
    struct RawstorFrameHead head;
    struct RawstorFrameObjCreatePayload payload;
} RAWSTOR_PACKED;

/* OBJ_CREATE response payload. */
struct RawstorFrameObjCreatedPayload {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/* OBJ_RESIZE response payload. */
struct RawstorFrameObjResizedPayload {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/*
 * OBJ_OPEN response payload: the descriptor followed by nchunks chunk
 * entries, each entry followed by its width slots
 * (RawstorFrameObjChunkEntry, then that many RawstorFrameObjChunkSlot
 * records).
 */
struct RawstorFrameObjDescriptorPayload {
    uint8_t id[16];
    uint64_t logical_size;
    uint64_t map_epoch;
    struct RawstorFrameObjPolicy policy;
    uint32_t nchunks;
    uint8_t chunk_shift; /* log2(chunk_size), see OBJ_CREATE's */
} RAWSTOR_PACKED;

struct RawstorFrameObjChunkEntry {
    uint8_t width; /* slots that follow */
} RAWSTOR_PACKED;

/*
 * ost_id is the stable identity (HRW); the location is advisory routing
 * data resolved by the MDS from its topology so that clients stay
 * zero-config: a rawstor location URI (e.g. ost://host:port), carried as
 * the location_len bytes (not null-terminated) right after this record.
 * location_len is 0 when the topology no longer lists the OST (the client
 * treats such a member as unreachable).
 */
struct RawstorFrameObjChunkSlot {
    uint8_t ost_id[16];
    uint16_t location_len;
    uint8_t slot_index;
} RAWSTOR_PACKED;

/*
 * OBJ_SNAP_COMMIT request: the payload is followed by nmembers member
 * records -- the chunk copies that actually hold the snapshot (the
 * IN-SYNC set at creation; a degraded object snapshots with less
 * redundancy, recorded, not repaired -- see Mds.md). snapshot_id is the
 * client's own already-generated version id (like every object id) --
 * never nil, nil is reserved for the live version.
 *
 * OBJ_SNAP_REMOVE rides RawstorFrameBasicPayload (object_id = id,
 * snapshot_id = the version to remove); its response payload is `res`
 * RawstorFrameObjSnapMemberPayload records: what was registered, for the
 * fan-out destroy.
 */
struct RawstorFrameObjSnapCommitPayload {
    uint8_t id[16];
    uint8_t snapshot_id[16];
    uint32_t nmembers;
} RAWSTOR_PACKED;

struct RawstorFrameObjSnapMemberPayload {
    uint64_t logical_index;
    uint8_t ost_id[16];
} RAWSTOR_PACKED;

/* OBJ_SNAP_COMMIT response payload. */
struct RawstorFrameObjSnapCommittedPayload {
    uint64_t map_epoch;
} RAWSTOR_PACKED;

/* Every wire struct's exact size, checked at compile time. */
#ifdef __cplusplus
#define RAWSTOR_PROTOCOL_ASSERT_SIZE(type, size)                               \
    static_assert(sizeof(struct type) == (size), #type " wire size")
#else
#define RAWSTOR_PROTOCOL_ASSERT_SIZE(type, size)                               \
    _Static_assert(sizeof(struct type) == (size), #type " wire size")
#endif

RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameHead, 8);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameBasicPayload, 48);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameListPayload, 20);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameListEntry, 24);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameIOPayload, 21);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameSyncStatePayload, 73);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameAllocatePayload, 48);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameResponseBody, 12);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameMetaPayload, 64);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameObjPolicy, 20);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameObjCreatePayload, 45);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameObjDescriptorPayload, 57);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameObjChunkSlot, 19);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameObjSnapCommitPayload, 36);
RAWSTOR_PROTOCOL_ASSERT_SIZE(RawstorFrameObjSnapMemberPayload, 24);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_PROTOCOL_H
