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
 * desired size of the object to be created, and mirror_count must equal the
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
    uint64_t size;             /**< Size of the object in bytes. */
    unsigned int mirror_count; /**< Number of URIs configured for the target. */
};

/**
 * Mirror consistency states of an object copy (see docs/mirroring.md).
 *
 * CLEAN   - the copy was closed correctly; all acknowledged writes are on it.
 * DIRTY   - the copy is open for writing; it may diverge from its mirrors in
 *           regions covered by unacknowledged writes.
 * SYNCING - a resync onto this copy was started and has not completed; the
 *           copy content must not be trusted.
 */
#define RAWSTOR_OBJECT_STATE_CLEAN 0u
#define RAWSTOR_OBJECT_STATE_DIRTY 1u
#define RAWSTOR_OBJECT_STATE_SYNCING 2u

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
    uint32_t state; /**< One of RAWSTOR_OBJECT_STATE_*. */
};

/**
 * @brief Object copy metadata.
 *
 * The full per-copy record: what the object is (spec, read-only here --
 * always the copy's own current size, not settable through this record)
 * plus this one copy's mirror consistency identity (sync_state, the part
 * rawstor_target_set_sync_state() can actually change).
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
 * (mirror_count -- computed locally from @p target, no backend involved).
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
 * @brief Asynchronously retrieve the full mirror consistency metadata of a
 *        target's first copy.
 *
 * Like rawstor_target_spec(), but fills the full per-copy metadata record
 * (RawstorObjectMeta) including the mirror consistency state, and only
 * ever queries the first URI of @p target -- unlike rawstor_target_spec(),
 * it does not fail over to the next one.
 *
 * Legacy copies created before metadata support report size only, with
 * state CLEAN, epoch 0 and sync_id 0.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes.
 *
 * @param queue   Queue used to drive the asynchronous lookup.
 * @param target  Target string, see rawstor_target_spec().
 * @param meta    Out-parameter written exactly once, immediately before
 *                @p cb is invoked: the copy's metadata on success. Left
 *                untouched on error, and never written at all if the
 *                lookup is never queued (see the return value below).
 * @param cb      Callback invoked on completion, see rawstor_target_spec().
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the lookup was successfully queued; negative errno on
 *         immediate failure (in which case neither @p meta nor @p cb is
 *         ever touched).
 *
 * @see RawstorObjectMeta
 * @see rawstor_target_spec
 */
int rawstor_target_meta(
    RawIOQueue* queue, const char* target, struct RawstorObjectMeta* meta,
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
 *                  expected size of the object. mirror_count is mandatory
 *                  and must equal the number of URIs in @p target (@c
 *                  -EINVAL otherwise, including when left 0). Only read
 *                  while this call is being queued -- need not stay valid
 *                  until @p cb runs.
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure (e.g. @c -EINVAL for invalid target or spec,
 *                    or a mirror_count that doesn't match @p target's own
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

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_TARGET_H
