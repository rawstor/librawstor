/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_TARGET_H
#define RAWSTOR_TARGET_H

#include <rawstor/list.h>
#include <rawstor/object.h>
#include <rawstor/rawio.h>
#include <rawstor/rawstor.h>

#include <stddef.h>
#include <stdint.h>

/**
 * @file target.h
 * @brief Object, logical chunk and physical member target APIs.
 *
 * The URI scheme selects how a target is accessed. An mds:// URI resolves
 * a logical object through its placement map; an explicit hexadecimal
 * offset selects one logical chunk. An ost:// URI addresses a physical
 * member directly, including a witness hosted by the MDS server. The
 * server endpoint may be the same while the access semantics differ.
 *
 * Logical chunk targets support metadata, configuration-register operations
 * and chunk-local I/O. Creating, removing, resizing or creating a version
 * of an MDS object requires a whole-object URI without a chunk offset.
 * Physical chunk targets are obtained with rawstor_target_chunks().
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Chunk member roles (docs/mds.md, chunk_meta.member_role). */
enum RawstorMemberRole {
    RAWSTOR_MEMBER_DATA = 1,
    RAWSTOR_MEMBER_WITNESS = 2, /**< Metadata-only quorum member. */
};

/**
 * @brief Object specification structure.
 *
 * Contains information about a stored object's own shape -- independent of
 * any single copy's consistency state (see RawstorObjectMeta for that).
 * This structure is used both for retrieving an existing object's
 * specification (via rawstor_target_spec()) and for specifying parameters
 * when creating a new object (via rawstor_target_create()).
 *
 * When used with rawstor_target_create(), the size field must be set to the
 * desired size of the object to be created; width is mandatory too, and
 * never defaulted or derived: it specifies data-copy redundancy, independent
 * of the physical URI count (a relay can itself contain several copies).
 * Use 1 for an ordinary single-copy object or the desired data redundancy
 * for an mds:// object. Zero is refused. chunk_size, when nonzero, must be a
 * power of two and size a multiple of it (@c -EINVAL otherwise): every chunk is
 * exactly chunk_size. It is mandatory for an mds:// object, and for a
 * target string naming more than one chunk's own uris (see
 * docs/concepts.md); 0 means one chunk spans the whole object, which then
 * can't be resized (rawstor_target_resize() only ever adds whole chunks).
 *
 * When used with rawstor_target_spec(), the fields are filled with the
 * actual shape of the existing object: its size in bytes, the number of
 * data copies configured for it -- the number of data URIs in the target string
 * for a plain target, or an mds:// object's own configured redundancy
 * (never derivable by counting URIs, since an mds:// target is always a
 * single URI) -- and the per-chunk share it was created with (0 for the
 * ordinary single-chunk case). rawstor_target_spec() only ever touches
 * the target's own first chunk, but chunk_size is the whole object's own
 * chunking policy, persisted identically on every chunk at create()
 * time, so any one of them answers it correctly.
 *
 * When a chunk has width + 1 locations, the last is a metadata-only witness.
 * At most one witness per chunk is supported, only with an even number of
 * data members. For a newly created mds:// object, an even data width
 * automatically places one additional witness in a distinct failure domain.
 * The topology must supply width + 1 eligible domains according to its
 * data/witness roles. MDS backends use ost:// with role witness. Physical
 * targets require the
 * witness URI to be supplied explicitly as the last member.
 *
 * @see rawstor_target_spec
 * @see rawstor_target_create
 */

struct RawstorObjectSpec {
    uint64_t size;      /**< Size of the object in bytes. */
    unsigned int width; /**< Data copies per chunk: the number of data URIs in a
                           plain target, or an mds:// object's own configured
                              redundancy. Mandatory at create() time -- see
                              rawstor_target_create()'s own doc comment. */

    /*
     * Object policy, mds:// targets only (docs/mds.md). Zeros are
     * defaults that degenerate to a single-chunk, single-copy object --
     * which behaves exactly like a plain object.
     */
    uint64_t chunk_size;         /**< Power of two dividing size; 0 = one
                                       chunk spans the object. */
    uint64_t stripe_width;       /**< K; 0 = spread every chunk, 1 =
                                       object-local. */
    unsigned int failure_domain; /**< RAWSTOR_OBJ_DOMAIN_*; 0 = default
                                  (server). */
};

/**
 * Mirror consistency states of an object copy (see docs/mirroring.md).
 *
 * UNREACHABLE - not a real copy state; the value a zero-initialized
 *               RawstorObjectMeta carries (e.g. rawstor_target_meta()'s
 *               entry for a URI that didn't answer). No real copy ever
 *               reports it, so a caller can tell "no answer" apart from
 *               a genuine (if unusual) CLEAN/epoch-0/sync_id-0 legacy
 *               copy by this field alone, without also having to check
 *               `size`.
 * CLEAN       - every session that wrote the copy left it cleanly; all
 *               acknowledged writes are on it.
 * DIRTY       - the copy is open for writing; it may diverge from its
 *               mirrors in regions covered by unacknowledged writes.
 * LOST        - DIRTY, and a session that wrote the copy went without a
 *               clean departure: the copy may differ from its mirrors in
 *               that writer's unacknowledged writes. It stays LOST until
 *               cleared explicitly (RAWSTOR_CONFIG_CLEAR_LOST), which a
 *               mirrored open does once it has made the copies equal.
 *
 * Witness members use the same states for their durable metadata record;
 * LOST invalidates their vote. They have no data writer sessions.
 *
 * The data copy keeps its state itself, from the sessions it serves
 * (docs/mirroring.md, "DIRTY, CLEAN and LOST"): it is read in
 * RawstorObjectMeta. Explicit metadata transitions use
 * the optional RawstorObjectSyncStateValue argument for any member.
 */
enum RawstorObjectSyncStateValue {
    RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE = 0,
    RAWSTOR_OBJECT_SYNC_STATE_CLEAN = 1,
    RAWSTOR_OBJECT_SYNC_STATE_DIRTY = 2,
    RAWSTOR_OBJECT_SYNC_STATE_LOST = 3,
};

/** Number of ancestor sync ids kept in RawstorObjectConfig. */
#define RAWSTOR_OBJECT_SYNC_ID_HISTORY 4

/** Most members a chunk can have: the role count fits a byte. */
#define RAWSTOR_OBJECT_MAX_WIDTH 255

/**
 * @brief A member's role in the chunk's configuration (docs/mirroring.md,
 *        "States and roles").
 *
 * UNKNOWN   - no configuration recorded for this member.
 * IN_SYNC   - the member carries every acknowledged write.
 * SYNCING   - an online resync onto the member was started and has not
 *             completed: its content must not be trusted.
 * EXCLUDED  - the member is out of the set.
 *
 * A role is the writer's decision about a member; a copy's own state
 * (RawstorObjectSyncStateValue) is what the copy knows of its writers.
 */
enum RawstorObjectMemberRole {
    RAWSTOR_OBJECT_MEMBER_UNKNOWN = 0,
    RAWSTOR_OBJECT_MEMBER_IN_SYNC = 1,
    RAWSTOR_OBJECT_MEMBER_SYNCING = 2,
    RAWSTOR_OBJECT_MEMBER_EXCLUDED = 3,
};

/**
 * @brief A proposal number of the chunk's configuration register
 *        (docs/caspaxos.md): ordered by counter, then by proposer.
 */
struct RawstorObjectBallot {
    uint64_t counter;
    uint64_t proposer;
};

/**
 * @brief The chunk's configuration, as a writer sets it on a copy.
 *
 * Its sync set (`epoch`, `sync_id` and its history) and every member's
 * role, in the order the chunk's members are listed (a plain target's
 * URIs, an mds:// chunk's placement). Written with
 * rawstor_target_set_member_config(), read back in RawstorObjectMeta. A
 * sync_id of 0 marks a legacy copy that has never been part of an
 * established sync set; such copies are treated as CLEAN and identical
 * right after creation.
 *
 * @see RawstorObjectMeta
 */
struct RawstorObjectConfig {
    uint64_t epoch;   /**< Bumped on every mirror-set health change. */
    uint64_t sync_id; /**< Id of the sync set this copy belongs to. */
    /** Ancestor sync ids, newest first; 0 marks unused entries. */
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    /** Writer running the resync of the syncing member, 0 when none. */
    uint64_t resync_owner;
    /** Number of entries in `roles`; 0 when no roles are recorded. */
    uint8_t nroles;
    /** enum RawstorObjectMemberRole per member, in member order. */
    uint8_t roles[RAWSTOR_OBJECT_MAX_WIDTH];
};

/**
 * rawstor_target_set_member_config() flag: a LOST copy becomes CLEAN (no
 * session open for writing) or DIRTY. For tooling that has made the
 * copies consistent by hand, e.g. `rawstor resolve`.
 */
#define RAWSTOR_CONFIG_CLEAR_LOST (1u << 0)

/**
 * @brief Object copy metadata.
 *
 * The full per-copy record, read-only: `spec` (unlike a RawstorObjectSpec
 * obtained through rawstor_target_spec()/_create(), which is used both
 * ways), the copy's own member_role, its own `state` and the number of
 * sessions open for writing on it right now (`writers`), both kept by the
 * copy itself, and the chunk's configuration as last written to it
 * (`config`, the part rawstor_target_set_member_config() sets). `config`
 * with `promised`/`accepted` is the copy's replica of the chunk's
 * configuration register (docs/multiattach.md, "The register").
 * `spec.width` is that copy's own persisted width -- the width
 * rawstor_target_create() was given -- reported verbatim; unlike
 * rawstor_target_spec(), nothing is recomputed locally.
 *
 * member_role lives here rather than on RawstorObjectSpec: unlike every
 * field RawstorObjectSpec actually carries, it isn't something every
 * copy of a chunk agrees on by construction -- a witness (docs/mds.md,
 * "Witness", stage 3) is a metadata-only member of the same chunk a
 * RAWSTOR_MEMBER_DATA copy also belongs to, so it's a property of one
 * particular copy, exactly like `state`, not of the chunk's own shape.
 *
 * @see rawstor_target_meta
 * @see rawstor_target_set_member_config
 */
struct RawstorObjectMeta {
    struct RawstorObjectSpec spec;
    enum RawstorMemberRole member_role;
    enum RawstorObjectSyncStateValue state;
    /** Sessions open for writing on the copy right now. */
    uint32_t writers;
    struct RawstorObjectConfig config;
    /** Highest ballot this copy promised. */
    struct RawstorObjectBallot promised;
    /** Ballot `config` was accepted under. */
    struct RawstorObjectBallot accepted;
};

/**
 * @brief Asynchronously retrieve metadata about a stored object.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function fills a RawstorObjectSpec structure with information about
 * the object: its size, and the number of copies configured for it (width
 * -- computed locally from @p target's own URI count for a plain target,
 * or the object's own configured redundancy for an mds:// one).
 *
 * The target may be a single location‑UUID pair or a comma‑separated list of
 * such pairs (mirroring / data locality). All UUIDs in a list must be
 * identical. The function queries backends in the order they appear until one
 * successfully returns the size.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue   Queue used to drive the asynchronous lookup.
 * @param target  Target string, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param spec    Out-parameter written exactly once, immediately before
 *                @p cb is invoked: the object's metadata on success. Left
 *                untouched on error, and never written at all if the lookup
 *                is never queued (see the return value below).
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure (@c -EINVAL for invalid target syntax --
 *                  malformed URI, empty list, duplicate URIs, mismatched
 *                  UUIDs --, @c -ENOENT if the object is not found on any of
 *                  the specified backends, @c -EIO for a network/filesystem
 *                  error, @c -EACCES if permission was denied).
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the lookup was successfully queued; negative errno on
 *         immediate failure (in which case neither @p spec nor @p cb is
 *         ever touched). The actual result is delivered via @p spec/@p cb.
 *
 * @see RawstorObjectSpec
 * @see Location and Target documentation in Rawstor user guide:
 * https://github.com/rawstor/librawstor/blob/main/docs/concepts.md
 */
int rawstor_target_spec(
    RawIOQueue* queue, const char* target, struct RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously retrieve the metadata of each member of a chunk.
 *
 * The chunk offset is encoded in @p target as a hexadecimal path segment,
 * e.g. @c ost://host:7777/UUID/40000000. Comma-separated URIs at the same
 * offset address the chunk's members, in the order returned in @p metas.
 * A plain target without an offset addresses offset zero. A whole-object
 * MDS target, @c mds://host:7776/UUID, resolves the first chunk through MDS;
 * @c mds://host:7776/UUID/OFFSET resolves the specified logical chunk and
 * neither form returns metadata for every chunk. Use rawstor_target_chunks()
 * to enumerate physical chunk targets and call this function for each one.
 * A target containing several distinct chunk offsets is rejected.
 *
 * Every member is queried. A member that cannot be read has a zero-filled
 * record with state RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE; this does not
 * fail the entire lookup. An MDS lookup failure is reported as an error.
 * A bound version in @p target selects that version's metadata.
 *
 * @param queue Queue used to drive the asynchronous lookup; must remain
 *              valid until completion.
 * @param target Non-NULL target string. Parsed before this call returns;
 *               the string need not remain valid until completion.
 * @param[out] metas Caller-owned array with room for @p count records.
 *                   May be NULL when @p count is zero. On success, the first
 *                   min(count, result) records are written before @p cb runs;
 *                   remaining entries are untouched. Not written on error.
 *                   The array must remain valid until completion.
 * @param count Capacity of @p metas, in records. Zero permits a size query.
 * @param cb Non-NULL completion callback. Its result is the required number
 *           of records on success, even if it exceeds @p count, or a negative
 *           errno on failure. Examples include @c -EINVAL for an invalid
 *           target or several chunk offsets, @c -ENOENT for an unknown MDS
 *           object, and @c -ENOMEM. Return zero, or a negative errno to report
 *           a callback error to the I/O completion machinery.
 * @param data Context pointer passed unchanged to @p cb.
 *
 * @return Zero if the lookup was queued; negative errno on immediate failure,
 *         in which case neither @p metas nor @p cb is touched. The return
 *         value is not the record count; that is delivered to @p cb.
 *
 * @see RawstorObjectMeta
 * @see rawstor_target_chunks
 * @see rawstor_target_offset
 */
int rawstor_target_meta(
    RawIOQueue* queue, const char* target, struct RawstorObjectMeta* metas,
    size_t count, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously replace one chunk member's configuration.
 *
 * The offset comes from @p target, and @p member_index selects a member in
 * rawstor_target_meta() order. A whole-object MDS target resolves the first
 * chunk; use rawstor_target_chunks() to address other chunks explicitly.
 * An MDS URI with an explicit offset resolves that logical chunk's members.
 * To address a witness stored on MDS directly, use an ost:// URI pointing
 * to the MDS server. A bound version is rejected: this operation modifies
 * live member metadata.
 *
 * Only the selected member is updated; this call neither gathers a quorum
 * nor updates other members. Configuration and an optional explicit state
 * are persisted by the selected backend before successful completion.
 *
 * @param queue Queue used to drive the operation; valid until completion.
 * @param target Non-NULL target string, parsed before this call returns.
 * @param member_index Zero-based member position in the addressed chunk.
 *                     An index outside the member list fails with @c -EINVAL.
 * @param config Non-NULL configuration to store. Copied before returning;
 *               it need not remain valid until completion.
 * @param flags Zero or RAWSTOR_CONFIG_CLEAR_LOST. The latter clears LOST
 *              according to the member's current writer state.
 * @param state Optional explicit state, or NULL to preserve the current
 *              state subject to @p flags. Copied before returning. An explicit
 *              state cannot be combined with RAWSTOR_CONFIG_CLEAR_LOST;
 *              RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE is not a stored state.
 * @param cb Non-NULL completion callback. Its result is zero on success or
 *           a negative errno on failure, such as @c -EINVAL for an invalid
 *           index, state, flags or bound version, or a backend I/O error.
 *           Return zero, or a negative errno to report a callback error.
 * @param data Context pointer passed unchanged to @p cb.
 *
 * @return Zero if queued; negative errno on immediate failure, in which case
 *         @p cb is not invoked. Completion status is delivered to @p cb.
 *
 * @warning This is an operator recovery operation. Changing one member's
 *          configuration without coordinating the others can desynchronize
 *          copies. Normal configuration changes use the configuration register.
 *
 * @see rawstor_target_meta
 * @see rawstor_target_sync_prepare
 * @see rawstor_target_sync_accept
 */
int rawstor_target_set_member_config(
    RawIOQueue* queue, const char* target, size_t member_index,
    const struct RawstorObjectConfig* config, unsigned int flags,
    const enum RawstorObjectSyncStateValue* state,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously request a configuration-register promise.
 *
 * This is phase 1 of the chunk's configuration register. The selected
 * member promises @p ballot if it is above both its promised ballot and
 * the ballot under which its configuration was accepted. The promise is
 * persisted before a successful reply. Both acceptance and refusal return
 * the member's record in @p meta, allowing the caller to inspect its
 * promised ballot and accepted configuration.
 *
 * The offset is taken from @p target. Member selection and MDS resolution
 * follow rawstor_target_set_member_config(); whole-object MDS targets
 * select the first chunk, and bound versions are rejected. One successful
 * promise is one member's vote; the caller coordinates the quorum.
 *
 * @param queue Queue used to drive the operation; valid until completion.
 * @param target Non-NULL target string, parsed before this call returns.
 * @param member_index Zero-based member position in rawstor_target_meta()
 *                     order, including a witness if present.
 * @param ballot Non-NULL proposed ballot. Copied before this call returns.
 * @param[out] meta Non-NULL caller-owned record. Filled before @p cb runs
 *                  with a nonnegative result; must remain valid until then.
 *                  Its contents must not be used after a failed operation.
 * @param cb Non-NULL completion callback. Its result is 1 if promised, 0 if
 *           refused, or a negative errno on failure. Refusal is a successful
 *           exchange, not an I/O error. Invalid targets or member indices
 *           fail with @c -EINVAL; a backend that cannot serve an individual
 *           member's register may report @c -ENOSYS. Return zero, or a negative
 *           errno to report a callback error.
 * @param data Context pointer passed unchanged to @p cb.
 *
 * @return Zero if queued; negative errno on immediate failure, in which case
 *         @p cb is not invoked. The promise decision is delivered to @p cb.
 *
 * @see RawstorObjectBallot
 * @see rawstor_target_sync_accept
 * @see rawstor_target_chunks
 */
int rawstor_target_sync_prepare(
    RawIOQueue* queue, const char* target, size_t member_index,
    const struct RawstorObjectBallot* ballot, struct RawstorObjectMeta* meta,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously request acceptance of a chunk configuration.
 *
 * This is phase 2 of the chunk's configuration register. The member accepts
 * when @p ballot is not below its promised ballot and is above the ballot
 * under which its configuration was accepted. It records @p config under
 * @p ballot and promises @p next if that ballot is above @p ballot. The
 * update is persisted before a successful reply. Acceptance and refusal
 * both return the member's record in @p meta.
 *
 * The offset comes from @p target. Member selection and MDS resolution
 * follow rawstor_target_set_member_config(); whole-object MDS targets
 * select the first chunk, and bound versions are rejected. Acceptance on
 * one member is one vote: the caller must obtain a majority of the
 * configuration register's acceptors. For two data members, a witness
 * supplies a third vote. This function does not copy or resynchronize data.
 *
 * @param queue Queue used to drive the operation; valid until completion.
 * @param target Non-NULL target string, parsed before this call returns.
 * @param member_index Zero-based member position in rawstor_target_meta()
 *                     order, including a witness if present.
 * @param ballot Non-NULL ballot under which to accept @p config.
 * @param next Non-NULL ballot to promise after acceptance when higher than
 *             @p ballot. Ballots are ordered by counter, then proposer.
 * @param config Non-NULL configuration proposed for the chunk. Both ballots
 *               and the configuration are copied before this call returns.
 * @param[out] meta Non-NULL caller-owned record. Filled before @p cb runs
 *                  with a nonnegative result; must remain valid until then.
 *                  Its contents must not be used after a failed operation.
 * @param cb Non-NULL completion callback. Its result is 1 if accepted, 0 if
 *           refused, or a negative errno on failure, including @c -EINVAL
 *           for an invalid target or member index and backend I/O errors.
 *           Refusal is not an I/O error. Return zero, or a negative errno
 *           to report a callback error.
 * @param data Context pointer passed unchanged to @p cb.
 *
 * @return Zero if queued; negative errno on immediate failure, in which case
 *         @p cb is not invoked. The acceptance decision is delivered to @p cb.
 *
 * @see RawstorObjectConfig
 * @see rawstor_target_sync_prepare
 * @see rawstor_target_chunks
 */
int rawstor_target_sync_accept(
    RawIOQueue* queue, const char* target, size_t member_index,
    const struct RawstorObjectBallot* ballot,
    const struct RawstorObjectBallot* next,
    const struct RawstorObjectConfig* config, struct RawstorObjectMeta* meta,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously create a new empty object at the specified target.
 *
 * @p target must be plain (no bound version, see
 * rawstor_target_version_id()) -- creating a version of an existing object
 * is rawstor_target_create_version()'s own job, never this function's; a
 * @p target that carries a bound version fails with @c -EINVAL.
 * This creates an object at the exact target location @p target names.
 * The object metadata (such as size) is provided via the @p spec
 * structure. The target string must follow the format described in the
 * Locations and Targets documentation (e.g., "ost://host:port/<uuid>" or
 * any other valid object identifier). The caller is responsible for
 * ensuring that the target is unique and that the backend can accept the
 * requested location; if the target already exists, the behaviour is
 * implementation‑defined (likely an error is returned).
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue     Queue used to drive the asynchronous create.
 * @param target    Target string specifying the full identifier of the
 *                  object to create, e.g., "ost://host:port/<uuid>". Must
 *                  not be NULL, must be a valid target as per the
 *                  library's format, and must not carry a bound version
 *                  version (see above).
 * @param spec      Pointer to a RawstorObjectSpec structure containing the
 *                  desired object shape. The size field must be set to the
 *                  expected size of the object. width is mandatory too (@c
 *                  -EINVAL if 0 or above 255): the object's redundancy
 *                  policy, persisted verbatim on every copy -- normally
 *                  @p target's own URI count when it names more than one,
 *                  but not required to be. Only read
 *                  while this call is being queued -- need not stay valid
 *                  until @p cb runs.
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure (e.g. @c -EINVAL for invalid target or spec,
 *                    or @p target carrying a bound version; @c -EIO
 *                    if no chunk member survived, mds:// target only; @c
 *                    -ENOMEM, etc; implementation‑defined beyond that).
 *                  - @p data is the same pointer passed as @p data below.
 *                  - Return zero on success. A negative errno value signals
 *                    an error back into the I/O completion machinery.
 * @param data      User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the create was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual create result is delivered via @p cb.
 *
 * @see RawstorObjectSpec
 * @see rawstor_target_create_version
 * @see rawstor_target_version_id
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/concepts.md
 */
int rawstor_target_create(
    RawIOQueue* queue, const char* target, const struct RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously remove an object -- or one of its versions --
 *        from the storage system.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function deletes the specified object from all backends listed in the
 * target. If the target contains multiple URIs (mirroring or locality),
 * the object is removed from every backend in the list.
 *
 * A @p target that carries a bound version (its own trailing
 * "/<offset>/<version_id>" path segments, present only alongside an explicit
 * offset -- see rawstor_target_version_id()) instead destroys that one
 * version -- there is no separate function for it: which identity gets
 * removed is already whatever @p target itself names, live object or a
 * specific version. For an mds://host:port/<id> @p target naming a
 * version, the MDS unregisters it (no new readers) before a
 * best-effort per-member fan-out destroy runs -- a member that can no
 * longer be resolved (location changed, OST replaced) is left for the
 * reconstruct scan rather than failing the call.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue   Queue used to drive the asynchronous remove.
 * @param target  Target string identifying the object (or bound version)
 *                to remove, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure (@c -EINVAL for invalid target syntax --
 *                  malformed URI, empty list, duplicate URIs, mismatched
 *                  UUIDs --, @c -ENOENT if the object is not found on one or
 *                  more backends, @c -EIO for a network/filesystem error,
 *                  @c -EACCES if permission was denied).
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the remove was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual remove result is delivered via @p cb.
 *
 * @see RawstorObjectSpec
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/concepts.md
 */
int rawstor_target_remove(
    RawIOQueue* queue, const char* target,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/** rawstor_target_open() flag: open read-only (see its own doc comment). */
#define RAWSTOR_READONLY 1

/** rawstor_target_open() flag: skip the quorum check (see its doc comment). */
#define RAWSTOR_FORCE 2

/**
 * @brief Asynchronously open an existing object for reading and/or writing.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function opens the specified object and, on success, delivers an
 * opaque handle that can be used for subsequent read/write operations via
 * @p cb. The object must already exist; otherwise, the operation completes
 * with an error.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * If the target contains multiple URIs (mirroring or data locality), the
 * library selects the appropriate backend(s) according to the location
 * policy defined for that target.
 *
 * The RawstorObject handle written to @p object must be closed with
 * rawstor_object_close() to release resources.
 *
 * @param queue   Queue used to drive the asynchronous open.
 * @param target  Target string identifying the object to open, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param flags   Open flags: 0, or a combination of RAWSTOR_READONLY and
 *                RAWSTOR_FORCE. A @p target that names a bound version
 *                (see rawstor_target_version_id()) can only be opened
 *                with RAWSTOR_READONLY (@c -EINVAL otherwise).
 *                RAWSTOR_READONLY makes every write to the resulting
 *                handle fail with @c -EROFS and records nothing (no
 *                mirror state, read-repair or resync), but a mirrored
 *                object still needs the same quorum as a writable open.
 *                RAWSTOR_FORCE | RAWSTOR_READONLY lifts that requirement:
 *                any reachable members are read from as-is. RAWSTOR_FORCE
 *                alone changes nothing -- a writable open never goes
 *                ahead without a quorum.
 * @param object  Out-parameter written exactly once, immediately before
 *                @p cb is invoked: the opaque handle on success, or NULL on
 *                error. The caller must not modify the pointed-to memory
 *                directly, and the pointer itself must stay valid until
 *                @p cb runs (never written if the open is never queued --
 *                see the return value below).
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure (@c -EINVAL for invalid target syntax --
 *                  malformed URI, empty list, duplicate URIs, mismatched
 *                  UUIDs --, @c -ENOENT if the object does not exist on any
 *                  of the specified backends, @c -EIO for a network/
 *                  filesystem error, @c -EACCES if permission was denied).
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the open was successfully queued; negative errno on
 *         immediate failure (in which case neither @p object nor @p cb is
 *         ever touched). The actual open result (success or failure) is
 *         delivered via @p object/@p cb.
 *
 * @see RawstorObject
 * @see rawstor_object_close
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/concepts.md
 */
int rawstor_target_open(
    RawIOQueue* queue, const char* target, int flags, RawstorObject** object,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve the UUID part of a target string.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function writes the target's unique identifier (UUID) into the
 * provided buffer. The UUID is the part after the last slash of each URI in
 * the target (e.g., for target
 * "ost://host:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00", the UUID is
 * "019cbfad-a389-7d42-a0f6-c29993ac8c00"). This is purely a syntactic
 * operation on @p target -- no backend is contacted, and the target need not
 * exist.
 *
 * If the buffer size is insufficient, the output is truncated but the
 * return value indicates the required buffer length (excluding the null
 * terminator), similar to snprintf().
 *
 * @param target  Target string, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param buf     Output buffer that will receive the UUID string. Can be NULL
 *                if only the required buffer length is needed.
 * @param size    Size of the output buffer in bytes (including space for the
 *                terminating null byte). If size is 0, no data is written, but
 *                the required length is still returned.
 *
 * @return On success, returns the number of characters that would have been
 *         written to buf (excluding the terminating null byte). If this value
 *         is non‑negative but greater than or equal to size, the output was
 *         truncated. A negative errno is returned if @p target is not valid
 *         target syntax.
 *
 * @see rawstor_target_location
 */
int rawstor_target_id(
    const char* target, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve the location part of a target string.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function writes a comma‑separated list of location URIs (i.e. @p target
 * with the UUID path segment stripped back off each URI) into the provided
 * buffer -- every URI @p target names, deduplicated (a plain target's own
 * URIs are already all distinct, but an mds://-internal multi-chunk string
 * can legitimately repeat the same backend across different chunks). This
 * is purely a syntactic operation on @p target -- no backend is contacted,
 * and the target need not exist.
 *
 * The format is the same as the location part of a target string, for example:
 *
 * - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *
 * - "file:///data/abc,ost://host1:9090/abc"      (locality)
 *
 * If the buffer size is insufficient, the output is truncated but the return
 * value indicates the required buffer length (excluding the null terminator),
 * similar to snprintf().
 *
 * @param target  Target string, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param buf     Output buffer that will receive the comma‑separated list of
 *                location URIs. Can be NULL if only the required buffer length
 *                is needed.
 * @param size    Size of the output buffer in bytes (including space for the
 *                terminating null byte). If size is 0, no data is written,
 *                but the required length is still returned.
 *
 * @return On success, returns the number of characters that would have been
 *         written to buf (excluding the terminating null byte). If this value
 *         is non‑negative but greater than or equal to size, the output was
 *         truncated. A negative errno is returned if @p target is not valid
 *         target syntax.
 *
 * @see rawstor_target_id
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/concepts.md
 */
int rawstor_target_location(
    const char* target, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously enumerate addressable chunk targets.
 *
 * For an MDS target, query MDS for the placement map and resolve
 * each selected chunk to its physical member URIs, such as
 * @c ost://host:7777/UUID/40000000. A whole-object URI selects all chunks;
 * an explicit offset selects one logical chunk. A witness stored on MDS has an
 * explicit physical URI such as @c ost://host:7776/UUID/40000000. The returned
 * strings do not redirect ordinary data-chunk operations through the logical
 * MDS object. When @p target binds a version, the returned URIs bind that same
 * version and describe its placement.
 *
 * Each list entry addresses one chunk; its comma-separated URIs name that
 * chunk's members in metadata/member-index order. Entries are ordered by
 * ascending byte offset. For a physical target, group its existing URIs by
 * offset without querying backends; a single chunk yields one entry. Such
 * a listing describes addresses and does not verify member reachability.
 *
 * The entries can be passed directly to rawstor_target_meta() or the
 * configuration-register operations. Read an entry's byte offset with
 * rawstor_target_offset().
 *
 * @param queue Queue used to drive the lookup; valid until completion.
 * @param target Non-NULL target string, parsed before this call returns.
 * @param[out] chunks Non-NULL output pointer. On success, receives a newly
 *                    allocated list, possibly empty, before @p cb runs.
 *                    Left untouched on failure. The pointer must remain
 *                    valid until completion. The caller owns the list and
 *                    releases it, including all strings, with
 *                    rawstor_string_list_delete(). Do not free strings
 *                    individually; they remain valid while the list exists.
 * @param cb Non-NULL completion callback. Its result is the number of chunk
 *           targets on success, or a negative errno on failure, such as
 *           @c -EINVAL for an invalid target, @c -ENOENT for an unknown MDS
 *           object, @c -ENOMEM, or an MDS communication error. Return zero,
 *           or a negative errno to report a callback error.
 * @param data Context pointer passed unchanged to @p cb.
 *
 * @return Zero if queued; negative errno on immediate failure, in which case
 *         neither @p chunks nor @p cb is touched. The count is delivered to
 *         @p cb, not returned directly.
 *
 * @see rawstor_string_list_iter
 * @see rawstor_string_list_next
 * @see rawstor_string_list_delete
 * @see rawstor_target_meta
 * @see rawstor_target_offset
 */
int rawstor_target_chunks(
    RawIOQueue* queue, const char* target, RawstorStringList** chunks,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously enumerate the physical member slots of a target.
 *
 * Each returned string contains exactly one physical member URI, suitable
 * for rawstor_target_meta() or direct member access. A chunk target with
 * several comma-separated member URIs produces one entry per member,
 * including a witness. Native witnesses hosted by MDS use ost:// URIs.
 *
 * A logical MDS chunk URI, mds://host:port/UUID/OFFSET, is resolved through
 * its placement map to the physical slots of that chunk. An offset-free
 * MDS object URI enumerates the slots of every chunk. Bound versions are
 * preserved in the returned URIs and resolved using their version's map.
 * Entries are ordered by ascending chunk byte offset and then by member
 * order within the chunk, matching rawstor_target_meta() indices for that
 * chunk. Slots on the same backend in different chunks remain separate.
 *
 * A physical target is split syntactically without contacting its members;
 * an MDS target contacts MDS to resolve placement. Unreachable member slots
 * are not omitted: enumeration describes addresses, not availability.
 *
 * @param queue Queue used to drive the lookup; valid until completion.
 * @param target Non-NULL target string. Parsed before this call returns;
 *               its storage need not remain valid until completion.
 * @param[out] slots Non-NULL output pointer, valid until completion. Before
 *                   a successful callback, receives a newly allocated list,
 *                   possibly empty. Left untouched on error. The caller
 *                   owns the list and frees it with
 *                   rawstor_string_list_delete(), which also frees every
 *                   string. Do not free individual strings; they remain
 *                   valid until the list is destroyed.
 * @param cb Non-NULL completion callback. Its result is the number of slots
 *           on success or a negative errno on failure, including @c -EINVAL
 *           for invalid target syntax, @c -ENOENT for an unknown logical
 *           chunk, @c -ENOMEM, or an MDS communication error. Return zero,
 *           or a negative errno to report a callback error.
 * @param data Context pointer passed unchanged to @p cb.
 *
 * @return Zero if queued; negative errno on immediate failure, in which
 *         case neither @p slots nor @p cb is touched. The slot count is
 *         delivered to @p cb, not returned directly.
 *
 * @see rawstor_target_chunks
 * @see rawstor_target_meta
 * @see rawstor_string_list_iter
 * @see rawstor_string_list_next
 * @see rawstor_string_list_delete
 */
int rawstor_target_slots(
    RawIOQueue* queue, const char* target, RawstorStringList** slots,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Extract the byte offset of a single chunk target.
 *
 * This is a synchronous syntax-only operation: no backend is contacted and
 * the chunk need not exist. The offset path segment is hexadecimal, while
 * the value written to @p offset is a byte count. For example,
 * @c ost://host:7777/UUID/40000000 yields 1073741824 (1 GiB).
 * A bound version after the offset does not change the extracted value.
 *
 * Comma-separated member URIs are accepted if they address the same chunk
 * (all have the same offset). An ordinary non-MDS target with no explicit
 * offset denotes offset zero. A whole-object MDS URI without an explicit
 * offset is rejected, because it denotes a logical object rather than a
 * chunk; @c mds://host:7776/UUID/0 explicitly selects a logical chunk
 * at offset zero and is accepted. Use rawstor_target_chunks() to resolve
 * its physical members; native witnesses on MDS use ost:// URIs.
 *
 * @param target Non-NULL target string identifying a single chunk, e.g. an
 *               entry returned by rawstor_target_chunks().
 * @param[out] offset Non-NULL caller-owned output, written only on success.
 *
 * @return Zero on success; negative errno on failure. @c -EINVAL means
 *         invalid target syntax, several chunk offsets, or a whole-object
 *         MDS target; @c -ENOMEM indicates an allocation failure.
 *
 * @see rawstor_target_chunks
 * @see rawstor_target_id
 * @see rawstor_target_version_id
 */
int rawstor_target_offset(
    const char* target, uint64_t* offset
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously list every version of the object a target
 *        addresses.
 *
 * Each version is reported as its own target string: every URI of
 * @p target (with any version it is bound to stripped off) followed by the
 * version's id -- the same string rawstor_target_create_version() prints,
 * ready for rawstor_target_open()/_spec()/_remove(). Oldest first
 * (version ids are UUID v7). For an mds:// target the MDS answers;
 * otherwise every copy of the object's first chunk is asked and their
 * answers merged, a copy that doesn't answer being skipped. A backend
 * without versions (file://, classic LVM) reports none.
 *
 * @param queue      Queue used to drive the asynchronous lookup.
 * @param target     Target string, see rawstor_target_id().
 * @param versions  On success, receives a newly allocated list of version
 *                   target strings, possibly empty (free it with
 *                   rawstor_string_list_delete()); left untouched on
 *                   failure. Must stay valid until @p cb runs.
 * @param cb         Callback invoked on completion.
 *                   - @p result is the number of versions on success, or
 *                     a negative errno on failure (e.g. @c -ENOTCONN if no
 *                     copy answered, @c -ENOENT for an mds:// object the MDS
 *                     doesn't know).
 *                   - @p data is the same pointer passed as @p data below.
 * @param data       User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the lookup was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked).
 *
 * @see rawstor_target_create_version
 * @see rawstor_string_list_delete
 */
int rawstor_target_versions(
    RawIOQueue* queue, const char* target, RawstorStringList** versions,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve the version bound to a target string.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function reads the trailing version path segment (if any) off
 * @p target's own path, in either of two equivalent shapes: logical
 * (`<uuid>/<version_id>`, the shape a caller types for a plain target's own
 * bound version -- no chunk-offset concept to name at that level) or
 * physical (`<uuid>/<offset>/<version_id>`, offset never omitted even "0" --
 * the shape internally used for one chunk of a larger mds:// object). This
 * is purely a syntactic operation on @p target -- no backend is contacted,
 * and the target need not exist.
 *
 * @param target   Target string, e.g.:
 *                 - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                 -
 * "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00/019cbfad-..."
 * @param buf      Output buffer for the bound version's UUID string, or an
 *                 empty string if @p target carries no bound version
 *                 (the live version). Same truncation convention as
 *                 rawstor_target_id().
 * @param size     Size of the output buffer in bytes (including space for the
 *                 terminating null byte). If size is 0, no data is written,
 *                 but the required length is still returned.
 *
 * @return On success, the number of characters that would have been written
 *         to buf (excluding the terminating null byte; 0 for the live
 *         version). A negative errno if @p target is not valid target
 *         syntax.
 *
 * @see rawstor_target_create
 * @see rawstor_target_remove
 * @see rawstor_target_chunks
 */
int rawstor_target_version_id(
    const char* target, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously create a version of a target, under whichever
 *        version id @p target/@p version_id together resolve to, and
 *        return the resulting target string.
 *
 * Every version id is client-generated, like every object id (see
 * rawstor_location_create()) -- there is no MDS-assigned mode: an
 * mds://host:port/<id> @p target's own MDS just registers whichever id
 * the caller already generated and embedded in the resulting target, once every
 * reachable chunk member has been backend-CoW'd under it (docs/mds.md,
 * "Versions (stage 2)"). Three ways the id actually used is picked, all
 * resolved synchronously (no I/O needed for any of them):
 * - @p target already names a specific version of its own (its own path
 *   carries a trailing version_id -- e.g. as read back by
 *   rawstor_target_version_id(), or as this same function itself already
 *   printed into a previous @p version_target) and @p version_id here is
 *   NULL: that bound version IS the one taken -- @p target itself is
 *   already the version's own target string.
 * - @p target names a plain object and @p version_id here is NULL: a
 *   fresh id is generated (rawstd_uuid7_init(), the same single point of
 *   generation a fresh object id comes from -- rawstor_location_create()).
 * - @p version_id here is non-NULL: that caller-chosen version id is used
 *   verbatim -- but only if @p target names a plain object; combining it
 *   with a @p target that already carries its own bound version is
 *   ambiguous and fails with @c -EINVAL instead.
 *
 * This then creates a plain native CoW version with that exact id on
 * every URI in @p target (every URI is still attempted even if an earlier
 * one fails, and the first error encountered is reported); the caller
 * owns crash consistency -- all acknowledged writes must be flushed
 * before this call. The resulting target string -- @p target itself when
 * already bound, or @p target with the id actually used spliced onto every
 * URI otherwise, i.e. exactly what rawstor_target_version_id() would read
 * back off it -- is written into @p version_target, the same synchronous,
 * before-any-I/O, snprintf()-style convention as rawstor_location_create()'s
 * own @p target/@p size:
 * - If the string fits, it is written before this call returns, the
 *   version is queued, and @p cb eventually reports the string's length
 *   (excluding the terminating null; always less than @p size) once the
 *   version is taken, or a negative errno if that fails.
 * - If @p version_target is too small, no version is taken and @p cb is
 *   invoked synchronously, from within this same call, with the required
 *   length (excluding the terminating null; always >= @p size).
 *
 * @param queue    Queue used to drive the asynchronous operation.
 * @param target   Target string, see rawstor_target_spec().
 * @param version_id  The version id's UUID string, or NULL -- see above.
 * @param version_target  Output buffer for the version's own target
 *                 string (may be NULL when @p size is 0), written
 *                 synchronously before this call returns
 *                 -- same truncation convention as
 *                 rawstor_location_create()'s own @p target (size it the
 *                 same way, e.g. 65536 bytes, not rawstor_target_id()'s
 *                 much smaller UUID-sized buffer).
 * @param size     Size of @p version_target in bytes (including space for
 *                 the terminating null byte).
 * @param cb       Callback invoked on completion.
 *                 - @p result is the version target string's length (see
 *                   above) on success or when @p version_target was too
 *                   small, or a negative errno on failure (@c -ENOTSUP if a
 *                   backend has no CoW --
 *                   file://, classic LVM -- no fallback copies are made
 *                   behind the caller's back; @c -EIO if no chunk member
 *                   survived, mds:// target only).
 *                 - @p data is the same pointer passed as @p data below.
 * @param data     User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if @p cb has been (or will be) invoked -- synchronously
 *         (buffer too small) or once version creation completes; negative errno
 *         on immediate failure (e.g. @c -EINVAL if @p target already names
 *         its own bound version and @p version_id is also non-NULL), in
 *         which case @p cb is never invoked.
 *
 * @see rawstor_target_create
 * @see rawstor_target_remove
 */
int rawstor_target_create_version(
    RawIOQueue* queue, const char* target, const char* version_id,
    char* version_target, size_t size, int (*cb)(ssize_t result, void* data),
    void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously grow an mds:// object to a new logical size.
 *
 * A logical chunk URI with an explicit offset is rejected with @c -EINVAL;
 * resize the whole object using its offset-free MDS URI.
 *
 * Grow-only: a @p new_size smaller than the object's current size fails
 * with -EINVAL (docs/mds.md -- shrink interacts with GC and
 * versions, deferred past v1). Reserves placement for whatever new
 * chunks the larger size needs on the MDS, then materializes exactly
 * those (not the whole map) on their OSTs -- existing chunks and their
 * data are untouched.
 *
 * @param queue     Queue used to drive the asynchronous resize.
 * @param target    An mds://host:port/<id> target; anything else
 *                  fails with -EINVAL (a plain target has no notion of
 *                  growing -- its size is fixed at create()).
 * @param new_size  The object's new logical size in bytes; must be
 *                  greater than or equal to its current size and a
 *                  multiple of its chunk_size (@c -EINVAL otherwise).
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure.
 *                  - @p data is the same pointer passed as @p data below.
 * @param data      User-defined context pointer passed unchanged to
 *                  @p cb.
 *
 * @return 0 if the resize was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked).
 */
int rawstor_target_resize(
    RawIOQueue* queue, const char* target, uint64_t new_size,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_TARGET_H
