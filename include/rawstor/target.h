/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_TARGET_H
#define RAWSTOR_TARGET_H

#include <rawstor/object.h>
#include <rawstor/rawio.h>
#include <rawstor/rawstor.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Chunk member kinds (docs/mds.md, chunk_meta.member_kind). */
enum RawstorMemberKind {
    RAWSTOR_MEMBER_DATA = 0,
    RAWSTOR_MEMBER_WITNESS = 1, /**< Metadata-only quorum member; stage 3. */
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
 * desired size of the object to be created, and mirrors must equal the
 * number of URIs in the target string being created -- mandatory, not a
 * convenience the caller can opt out of (mismatch, including leaving it 0,
 * fails the create with -EINVAL): a caller that doesn't already know the
 * count can derive it by counting the ','-separated entries in its own
 * target/location string.
 *
 * When used with rawstor_target_spec(), both fields are filled with the
 * actual shape of the existing object: its size in bytes and the number of
 * URIs configured for it.
 *
 * @see rawstor_target_spec
 * @see rawstor_target_create
 */

struct RawstorObjectSpec {
    uint64_t size;        /**< Size of the object in bytes. */
    unsigned int mirrors; /**< Number of URIs configured for the target. */

    /*
     * Object policy, mds:// targets only (docs/mds.md). Zeros are
     * defaults that degenerate to a single-chunk, single-copy object --
     * which behaves exactly like a plain object.
     */
    uint64_t chunk_size;    /**< Power of two; 0 = one chunk spans the
                                  object. */
    uint64_t stripe_width;  /**< K; 0 = spread every chunk, 1 =
                                  object-local. */
    uint8_t width;          /**< Copies per chunk; 0 = 1. */
    uint8_t failure_domain; /**< RAWSTOR_OBJ_DOMAIN_*; default server. */

    /*
     * Placement identity of a chunk object (docs/mds.md, chunk_meta),
     * minus the parts a caller already has to hand: the resource's own
     * name is self-describing (docs/mds.md, "Chunk identity" -- obj_id =
     * id) -- a chunk's own id is exactly the id its own target
     * string carries, and its logical_index is chunk_offset / chunk_size
     * (the target string's own offset path segment,
     * rawstor_target_offset()). Nothing here needs to repeat either.
     */
    enum RawstorMemberKind member_kind;
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
 * CLEAN       - the copy was closed correctly; all acknowledged writes are
 *               on it.
 * DIRTY       - the copy is open for writing; it may diverge from its
 *               mirrors in regions covered by unacknowledged writes.
 * SYNCING     - a resync onto this copy was started and has not completed;
 *               the copy content must not be trusted.
 */
enum RawstorObjectSyncStateValue {
    RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE = 0,
    RAWSTOR_OBJECT_SYNC_STATE_CLEAN = 1,
    RAWSTOR_OBJECT_SYNC_STATE_DIRTY = 2,
    RAWSTOR_OBJECT_SYNC_STATE_SYNCING = 3,
};

/** Number of ancestor sync ids kept in RawstorObjectMeta. */
#define RAWSTOR_OBJECT_SYNC_ID_HISTORY 4

/**
 * @brief Settable mirror consistency identity of a single object copy.
 *
 * Everything about a copy's consistency state that can actually be changed
 * (see docs/mirroring.md) -- the fields rawstor_target_set_sync_state()
 * persists. A sync_id of 0 marks a legacy copy that has never been part of
 * an established sync set; such copies are treated as CLEAN and identical
 * right after creation.
 *
 * @see RawstorObjectMeta
 * @see rawstor_target_meta
 */
struct RawstorObjectSyncState {
    uint64_t epoch;   /**< Bumped on every mirror-set health change. */
    uint64_t sync_id; /**< Id of the sync set this copy belongs to. */
    /** Ancestor sync ids, newest first; 0 marks unused entries. */
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    enum RawstorObjectSyncStateValue state;
};

/**
 * @brief Object copy metadata.
 *
 * The full per-copy record: `spec` (read-only here, not settable through
 * this record -- unlike a RawstorObjectSpec obtained through
 * rawstor_target_spec()/_create(), which is used both ways) plus this
 * copy's mirror consistency identity (sync_state, the part
 * rawstor_target_set_sync_state() can actually change). `spec.mirrors`
 * is filled in by rawstor_target_meta() itself the same way
 * rawstor_target_spec() fills its own -- the number of URIs in the
 * target string, computed locally -- not by the backend that answered:
 * mirrors isn't a property of any single copy.
 *
 * @see rawstor_target_meta
 * @see rawstor_target_set_sync_state
 */
struct RawstorObjectMeta {
    struct RawstorObjectSpec spec;
    struct RawstorObjectSyncState sync_state;
};

/**
 * @brief Asynchronously retrieve metadata about a stored object.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function fills a RawstorObjectSpec structure with information about
 * the object: its size, and the number of URIs configured for it
 * (mirrors -- computed locally from @p target, no backend involved).
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
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_target_spec(
    RawIOQueue* queue, const char* target, struct RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously retrieve the full mirror consistency metadata of
 *        every copy of a target.
 *
 * Like rawstor_target_spec(), but queries every URI in @p target
 * concurrently and fills one RawstorObjectMeta per URI, in @p target's
 * own order -- unlike rawstor_target_spec()'s single-answer fail-over
 * tolerance, this reports every copy's own state, not just one answer
 * standing in for the whole set. A URI that doesn't answer (unreachable,
 * ENOENT, ...) gets an entry with `sync_state.state ==
 * RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE` rather than failing the whole
 * call or being left out -- the entry's own position in @p metas is what
 * ties it back to that URI, so skipping it would lose that. `spec.mirrors`
 * in every entry that did answer is filled in the same way
 * rawstor_target_spec() fills its own -- the number of URIs in @p target,
 * computed locally -- not whatever the answering copy's own backend
 * happened to report.
 *
 * Legacy copies created before metadata support report size only, with
 * state CLEAN, epoch 0 and sync_id 0 -- distinguishable from a URI that
 * didn't answer at all by `state` alone (`RAWSTOR_OBJECT_SYNC_STATE_CLEAN`
 * vs `_UNREACHABLE`).
 *
 * An mds://host:port/<id> @p target is, from this call's own
 * point of view, an ordinary single-URI target -- it succeeds with one
 * synthetic entry: `spec` reflects the object's own logical size/chunk_size/
 * policy, `sync_state` a "legacy copy" CLEAN/epoch-0/sync_id-0 answer. The
 * real per-chunk DIRTY/CLEAN state (many chunks, each with its own slots)
 * is tracked one level down and not exposed through the object-level
 * target at all.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue   Queue used to drive the asynchronous lookup.
 * @param target  Target string, see rawstor_target_spec().
 * @param metas   Out-parameter: an array of @p count entries. Filled with
 *                one entry per URI in @p target (in order), up to
 *                @p count of them, immediately before @p cb is invoked.
 *                Left untouched on error, and never written at all if
 *                the lookup is never queued (see the return value
 *                below).
 * @param count   Capacity of @p metas.
 * @param cb      Callback invoked on completion.
 *                - @p result is the number of URIs in @p target on
 *                  success -- same truncation convention as
 *                  rawstor_target_id()/_location(): if it is greater than
 *                  @p count, only the first @p count entries were
 *                  actually written to @p metas, and the caller should
 *                  retry with a bigger buffer rather than treat this as
 *                  an error -- or a negative errno on failure (@c
 *                  -EINVAL for invalid target syntax, @c -ENOMEM).
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals
 *                  an error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the lookup was successfully queued; negative errno on
 *         immediate failure (in which case neither @p metas nor @p cb is
 *         ever touched).
 *
 * @see RawstorObjectMeta
 * @see rawstor_target_spec
 */
int rawstor_target_meta(
    RawIOQueue* queue, const char* target, struct RawstorObjectMeta* metas,
    size_t count, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously write the mirror consistency identity of every
 *        copy of a target.
 *
 * Unlike rawstor_target_spec()/rawstor_target_meta(), this writes rather
 * than reads: it sets @p sync_state on every URI in @p target
 * concurrently (fsynced on the backend before it is acknowledged, per
 * docs/mirroring.md's durability rule) -- every URI is still attempted
 * even if an earlier one fails, so a partial failure leaves as many
 * copies updated as possible rather than none.
 *
 * @warning Setting mirror consistency state by hand can desynchronize a
 * target's copies in ways the library's own quorum/reconciliation logic
 * (docs/mirroring.md) is not designed to recover from automatically --
 * this exists for tooling that already understands that model (e.g. a
 * `rawstor-cli resolve`-style split-brain recovery flow, or
 * `rawstor-ost` relaying an incoming wire `SET_SYNC_STATE` command), not
 * for routine application use.
 *
 * An mds://host:port/<id> @p target succeeds as a no-op --
 * mds::Backend's own consistency state is tracked one level down, per
 * chunk, not at the object level this call writes to (same reason
 * rawstor_target_meta() reports a synthetic answer instead of failing).
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue       Queue used to drive the asynchronous write.
 * @param target      Target string, see rawstor_target_spec().
 * @param sync_state  The mirror consistency identity to write to every
 *                    copy. Only read while this call is being queued --
 *                    need not stay valid until @p cb runs.
 * @param cb          Callback invoked on completion.
 *                    - @p result is zero on success, or a negative errno
 *                      on failure (@c -EINVAL for invalid target syntax,
 *                      or the first error any URI's own write failed
 *                      with).
 *                    - @p data is the same pointer passed as @p data
 *                      below.
 *                    - Return zero on success. A negative errno value
 *                      signals an error back into the I/O completion
 *                      machinery.
 * @param data        User-defined context pointer passed unchanged to
 *                    @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked).
 *
 * @see RawstorObjectSyncState
 * @see rawstor_target_meta
 */
int rawstor_target_set_sync_state(
    RawIOQueue* queue, const char* target,
    const struct RawstorObjectSyncState* sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously create a new empty object at the specified target.
 *
 * This function creates an object at the exact target location given by the
 * @p target string. The object metadata (such as size) is provided via the
 * @p spec structure. The target string must follow the format described in the
 * Locations and Targets documentation (e.g., "ost://host:port/<uuid>" or any
 * other valid object identifier). The caller is responsible for ensuring that
 * the target is unique and that the backend can accept the requested location;
 * if the target already exists, the behaviour is implementation‑defined (likely
 * an error is returned).
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue     Queue used to drive the asynchronous create.
 * @param target    Target string specifying the full identifier of the object
 *                  to be created (e.g., "ost://host:port/<uuid>"). Must not be
 *                  NULL and must be a valid target as per the library's format.
 * @param spec      Pointer to a RawstorObjectSpec structure containing the
 *                  desired object shape. The size field must be set to the
 *                  expected size of the object. mirrors is mandatory
 *                  and must equal the number of URIs in @p target (@c
 *                  -EINVAL otherwise, including when left 0). Only read
 *                  while this call is being queued -- need not stay valid
 *                  until @p cb runs.
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure (e.g. @c -EINVAL for invalid target or spec,
 *                    or a mirrors value that doesn't match @p target's own
 *                    URI count; @c -ENOMEM, @c -EIO, etc; implementation‑
 *                    defined beyond that).
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
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_target_create(
    RawIOQueue* queue, const char* target, const struct RawstorObjectSpec* spec,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously remove an object from the storage system.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function deletes the specified object from all backends listed in the
 * target. If the target contains multiple URIs (mirroring or locality),
 * the object is removed from every backend in the list.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue   Queue used to drive the asynchronous remove.
 * @param target  Target string identifying the object to remove, e.g.:
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
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_target_remove(
    RawIOQueue* queue, const char* target,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

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
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_target_open(
    RawIOQueue* queue, const char* target, RawstorObject** object,
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
 * buffer. This is purely a syntactic operation on @p target -- no backend is
 * contacted, and the target need not exist.
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
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_target_location(
    const char* target, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve the snapshot version bound to a target string.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function reads the trailing snapshot path segment (if any) off
 * @p target's own path -- present only alongside an explicit offset segment
 * (even "0"): a target string's identity is `<uuid>[/<offset>[/<snap_id>]]`,
 * offset never omitted once a snapshot follows it, so a bound version and an
 * unrelated trailing path segment of the target's own location can never be
 * confused for one another. This is purely a syntactic operation on
 * @p target -- no backend is contacted, and the target need not exist.
 *
 * @param target   Target string, e.g.:
 *                 - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                 -
 * "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00/0/019cbfad-..."
 * @param buf      Output buffer for the bound version's UUID string, or an
 *                 empty string if @p target carries no bound snapshot
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
 * @see rawstor_target_offset
 */
int rawstor_target_snap_id(
    const char* target, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve a target string's own byte offset within its parent
 *        mds:// object.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function reads the offset path segment (if any) right after @p
 * target's own UUID path segment -- present only on a chunk of an mds://
 * object opened internally by the library (mds::Backend's own internal
 * target strings; a plain, user-facing target never carries one, unless it
 * also has a bound snapshot -- see rawstor_target_snap_id()). This is purely
 * a syntactic operation on @p target -- no backend is contacted, and the
 * target need not exist.
 *
 * @param target  Target string, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 * @param offset  Out-parameter written on success: the target's own byte
 *                offset within its parent object, or 0 if @p target carries
 *                no offset path segment. Left untouched on error.
 *
 * @return 0 on success; a negative errno if @p target is not valid target
 *         syntax.
 *
 * @see rawstor_target_snap_id
 */
int rawstor_target_offset(
    const char* target, uint64_t* offset
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously take a snapshot of a target under a fresh or
 *        caller-chosen version id.
 *
 * Every version id is client-generated, like every object id (see
 * rawstor_location_create()) -- there is no more MDS-assigned mode: an
 * mds://host:port/<id> @p target's own MDS no longer hands out the id
 * itself, it just registers whichever one this call already generated or
 * was given, once every reachable chunk member has been backend-CoW'd
 * under it (docs/mds.md, "Snapshots (stage 2)"). A non-mds:// @p target
 * instead takes a plain native CoW snapshot as that exact version on
 * every URI in @p target (every URI is still attempted even if an
 * earlier one fails, and the first error encountered is reported); the
 * caller owns crash consistency there -- all acknowledged writes must be
 * flushed before this call.
 *
 * @param queue    Queue used to drive the asynchronous snapshot.
 * @param target   Target string, see rawstor_target_spec().
 * @param snap_id  The version id's UUID string, or NULL to have this call
 *                 generate a fresh one itself (rawstd_uuid7_init(), the
 *                 same single point of generation a fresh object id comes
 *                 from -- rawstor_location_create()).
 * @param buf      Output buffer for the version id actually used (whether
 *                 generated here or supplied in @p snap_id), written
 *                 synchronously before this call returns -- same
 *                 truncation convention as rawstor_target_id().
 * @param size     Size of @p buf in bytes (including space for the
 *                 terminating null byte).
 * @param cb       Callback invoked on completion.
 *                 - @p result is zero on success, or a negative errno on
 *                   failure (@c -ENOTSUP if a backend has no CoW --
 *                   file://, classic LVM -- no fallback copies are made
 *                   behind the caller's back; @c -EIO if no chunk member
 *                   survived, mds:// target only).
 *                 - @p data is the same pointer passed as @p data below.
 * @param data     User-defined context pointer passed unchanged to @p cb.
 *
 * @return The number of characters written to @p buf (see
 *         rawstor_target_id()) if the snapshot was successfully queued;
 *         negative errno on immediate failure (in which case @p cb is
 *         never invoked).
 *
 * @see rawstor_target_snapshot_remove
 */
int rawstor_target_snapshot_create(
    RawIOQueue* queue, const char* target, const char* snap_id, char* buf,
    size_t size, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously destroy snapshot version @p snap_id of a target.
 *
 * For an mds://host:port/<id> @p target, the MDS unregisters
 * @p snap_id (no new readers) before a best-effort per-member fan-out
 * destroy runs -- a member that can no longer be resolved (address
 * changed, OST replaced) is left for the reconstruct scan rather than
 * failing the call. For any other @p target, this is instead a plain
 * fan-out over every URI (same semantics as the native CoW branch of
 * rawstor_target_snapshot_create()): every URI is attempted, the first
 * error is reported.
 *
 * @param snap_id  The version id's UUID string -- always the caller's own,
 *                 never generated here (there is nothing left to report
 *                 back: the caller already knows which snapshot it means
 *                 to remove).
 *
 * @return 0 if the removal was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked).
 *
 * @see rawstor_target_snapshot_create
 */
int rawstor_target_snapshot_remove(
    RawIOQueue* queue, const char* target, const char* snap_id,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously grow an mds:// object to a new logical size.
 *
 * Grow-only: a @p new_size smaller than the object's current size fails
 * with -EINVAL (docs/mds.md -- shrink interacts with GC and
 * snapshots, deferred past v1). Reserves placement for whatever new
 * chunks the larger size needs on the MDS, then materializes exactly
 * those (not the whole map) on their OSTs -- existing chunks and their
 * data are untouched.
 *
 * @param queue     Queue used to drive the asynchronous resize.
 * @param target    An mds://host:port/<id> target; anything else
 *                  fails with -EINVAL (a plain target has no notion of
 *                  growing -- its size is fixed at create()).
 * @param new_size  The object's new logical size in bytes; must be
 *                  greater than or equal to its current size.
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
