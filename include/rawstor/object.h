/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

#include <rawstor/rawio.h>
#include <rawstor/rawstor.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorObject RawstorObject;

/**
 * @brief Object metadata structure.
 *
 * Contains information about a stored object. This structure is used both for
 * retrieving existing object metadata (via rawstor_object_spec()) and for
 * specifying parameters when creating a new object (via
 * rawstor_object_create()).
 *
 * When used with rawstor_object_create(), the size field must be set to the
 * desired size of the object to be created.
 *
 * When used with rawstor_object_spec(), the size field is filled with the
 * actual size of the existing object in bytes.
 *
 * @see rawstor_object_spec
 * @see rawstor_object_create
 */
struct RawstorObjectSpec {
    uint64_t size; /**< Size of the object in bytes. */
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
 * @brief Object copy metadata.
 *
 * Extends RawstorObjectSpec with the mirror consistency state of a single
 * object copy (see docs/mirroring.md). A sync_id of 0 marks a legacy copy
 * that has never been part of an established sync set; such copies are
 * treated as CLEAN and identical right after creation.
 *
 * @see rawstor_object_meta
 * @see rawstor_object_set_state
 */
struct RawstorObjectMeta {
    uint64_t size;    /**< Size of the object in bytes. */
    uint64_t epoch;   /**< Bumped on every mirror-set health change. */
    uint64_t sync_id; /**< Id of the sync set this copy belongs to. */
    /** Ancestor sync ids, newest first; 0 marks unused entries. */
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    uint32_t state; /**< One of RAWSTOR_OBJECT_STATE_*. */
};

typedef int(RawstorCallback)(
    RawstorObject* object, size_t size, size_t result, int error, void* data
);

/**
 * @brief Retrieve metadata about a stored object.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function fills a RawstorObjectSpec structure with information about the
 * object, such as its size.
 *
 * The target may be a single location‑UUID pair or a comma‑separated list of
 * such pairs (mirroring / data locality). All UUIDs in a list must be
 * identical. The function queries backends in the order they appear until one
 * successfully returns the metadata.
 *
 * @param target  Target string, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param spec    Pointer to a RawstorObjectSpec structure that will be
 *                filled with the object's metadata on success.
 *
 * @return 0 on success, negative errno on error.
 * @retval 0        Object metadata successfully retrieved.
 * @retval -EINVAL  Invalid target syntax (e.g., malformed URI, empty list,
 *                  duplicate URIs, mismatched UUIDs).
 * @retval -ENOENT  Object not found on any of the specified backends.
 * @retval -EIO     I/O error (network or filesystem).
 * @retval -EACCES  Permission denied.
 *
 * @see RawstorObjectSpec
 * @see Location and Target documentation in Rawstor user guide:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_spec(
    const char* target, struct RawstorObjectSpec* spec
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve full metadata of a stored object copy.
 *
 * Like rawstor_object_spec(), but fills the full per-copy metadata record
 * including the mirror consistency state. Only the first target of a
 * comma-separated list is queried.
 *
 * Legacy copies created before metadata support report size only, with
 * state CLEAN, epoch 0 and sync_id 0.
 *
 * @param target  Target string, see rawstor_object_spec().
 * @param meta    Pointer to a RawstorObjectMeta structure that will be
 *                filled with the copy's metadata on success.
 *
 * @return 0 on success, negative errno on error.
 *
 * @see RawstorObjectMeta
 * @see rawstor_object_spec
 */
int rawstor_object_meta(
    const char* target, struct RawstorObjectMeta* meta
) RAWSTOR_NOEXCEPT;

/**
 * @brief Update the mirror consistency state of an object.
 *
 * Persists the state, epoch, sync_id and sync_id_history fields of @p meta
 * on every backend listed in @p target; the first error encountered is
 * reported. The object size cannot be changed through this call: the size
 * field of @p meta is ignored and the stored size is preserved.
 *
 * The update is durable: it is synced to stable storage before the call
 * completes successfully.
 *
 * @param target  Target string, see rawstor_object_spec().
 * @param meta    Metadata record to persist (size field ignored).
 *
 * @return 0 on success, negative errno on error.
 *
 * @see RawstorObjectMeta
 * @see rawstor_object_meta
 */
int rawstor_object_set_state(
    const char* target, const struct RawstorObjectMeta* meta
) RAWSTOR_NOEXCEPT;

/**
 * @brief Create a new empty object at the specified target.
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
 * @param target    Target string specifying the full identifier of the object
 *                  to be created (e.g., "ost://host:port/<uuid>"). Must not be
 *                  NULL and must be a valid target as per the library's format.
 * @param spec      Pointer to a RawstorObjectSpec structure containing the
 *                  desired object metadata (e.g., size in bytes). The size
 *                  field must be set to the expected size of the object.
 *
 * @return 0 on success.
 * @retval Negative value on error (e.g., -EINVAL for invalid target or spec,
 *         -ENOMEM, -EIO, etc.). The specific negative errno codes are
 *         implementation‑defined.
 *
 * @see RawstorObjectSpec
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_create(
    const char* target, const struct RawstorObjectSpec* spec
) RAWSTOR_NOEXCEPT;

/**
 * @brief Create an empty object at the specified location with optional UUID,
 *        and return the constructed target string.
 *
 * This function creates a new object at the given @p location. If @p uuid is
 * NULL, the library automatically generates a unique UUID for the object;
 * otherwise, the provided UUID is used. The object metadata (size, etc.) is
 * provided via the @p spec structure.
 *
 * The function constructs the full target identifier from @p location and
 * @p uuid according to the library's target format (e.g.,
 * "ost://host:port/<uuid>"). It then attempts to copy the resulting string into
 * the caller‑supplied buffer @p target of size @p size bytes, **including** the
 * terminating null character.
 *
 * The return value follows the semantics of `snprintf()`:
 * - On success (i.e., the entire target string fits in the buffer), the object
 *   is created, the full string (including the null terminator) is written to
 *   @p target, and the function returns the number of characters that would
 *   have been written (excluding the terminating null) – which is always
 *   less than @p size.
 * - If the buffer is too small to hold the complete target string, the object
 *   is **not** created, no data is written to @p target (or the buffer may be
 *   left unchanged), and the function returns the number of characters that
 *   would have been required (excluding the null terminator). This is exactly
 *   the same behaviour as `snprintf()` when the buffer is too small, except
 *   that here the object creation is aborted.
 * - On other errors (e.g., invalid parameters, memory allocation failure, I/O
 *   problems), a negative error code is returned.
 *
 * @param location  Location string specifying the backend and endpoint
 *                  (e.g., "ost://host:port"). Must not be NULL and must be a
 *                  valid location as per the library's format.
 * @param uuid      UUID string for the object. If NULL, a UUID is automatically
 *                  generated. If not NULL, it must be a valid UUID string.
 * @param spec      Pointer to a RawstorObjectSpec structure containing the
 *                  desired object metadata (e.g., size in bytes). The size
 *                  field must be set to the expected size of the object.
 * @param target    Output buffer that will receive the full target string
 *                  (e.g., "ost://host:port/<uuid>"). Must not be NULL.
 * @param size      Size of the @p target buffer in bytes, including space for
 *                  the terminating null character. The buffer must be large
 *                  enough to hold the complete string; if not, the object is
 *                  not created and the required length is returned.
 *
 * @return On success (buffer large enough), returns the length of the target
 *         string (excluding the terminating null), which is less than @p size.
 *         If the buffer is too small, returns the required length (excluding
 *         the null terminator) and does **not** create the object.
 * @retval Negative value on errors (e.g., -EINVAL for invalid parameters,
 *         -ENOMEM, -EIO, etc.). The specific negative errno codes are
 *         implementation‑defined.
 *
 * @see RawstorObjectSpec
 * @see rawstor_object_create
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_create_at(
    const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Remove an object from the storage system.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function deletes the specified object from all backends listed in the
 * target. If the target contains multiple URIs (mirroring or locality),
 * the object is removed from every backend in the list.
 *
 * @param target  Target string identifying the object to remove, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 *
 * @return 0 on success, negative errno on error.
 * @retval 0        Object successfully removed from all backends.
 * @retval -EINVAL  Invalid target syntax (malformed URI, empty list, duplicate
 *                  URIs, mismatched UUIDs).
 * @retval -ENOENT  Object not found on one or more backends.
 * @retval -EIO     I/O error (network or filesystem).
 * @retval -EACCES  Permission denied.
 *
 * @see RawstorObjectSpec
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_remove(const char* target) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously retrieve metadata about a stored object.
 *
 * Non-blocking variant of rawstor_object_spec(). The operation is driven by
 * @p queue; @p cb is invoked exactly once from the queue completion context
 * with 0 on success or a negative errno value on failure. On success @p spec
 * is filled before @p cb is invoked; it must stay valid until then.
 *
 * @param queue   I/O queue that drives the operation.
 * @param target  Target string, see rawstor_object_spec().
 * @param spec    Pointer to a RawstorObjectSpec structure that will be
 *                filled with the object's metadata on success. Must stay
 *                valid until @p cb is invoked.
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_spec
 */
int rawstor_object_spec_async(
    RawIOQueue* queue, const char* target, struct RawstorObjectSpec* spec,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously retrieve full metadata of a stored object copy.
 *
 * Non-blocking variant of rawstor_object_meta(). The operation is driven by
 * @p queue; @p cb is invoked exactly once from the queue completion context
 * with 0 on success or a negative errno value on failure. On success @p meta
 * is filled before @p cb is invoked; it must stay valid until then.
 *
 * @param queue   I/O queue that drives the operation.
 * @param target  Target string, see rawstor_object_spec().
 * @param meta    Pointer to a RawstorObjectMeta structure that will be
 *                filled with the copy's metadata on success. Must stay
 *                valid until @p cb is invoked.
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_meta
 */
int rawstor_object_meta_async(
    RawIOQueue* queue, const char* target, struct RawstorObjectMeta* meta,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously update the mirror consistency state of an object.
 *
 * Non-blocking variant of rawstor_object_set_state(). The operation is
 * driven by @p queue; @p cb is invoked exactly once from the queue
 * completion context with 0 on success or a negative errno value on failure.
 *
 * @param queue   I/O queue that drives the operation.
 * @param target  Target string, see rawstor_object_spec().
 * @param meta    Metadata record to persist (size field ignored). Copied
 *                internally; does not need to stay valid after the call
 *                returns.
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_set_state
 */
int rawstor_object_set_state_async(
    RawIOQueue* queue, const char* target, const struct RawstorObjectMeta* meta,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously create a new empty object at the specified target.
 *
 * Non-blocking variant of rawstor_object_create(). The operation is driven
 * by @p queue; @p cb is invoked exactly once from the queue completion
 * context with 0 on success or a negative errno value on failure. If the
 * target contains multiple URIs (mirroring or locality), the object is
 * created on every backend in the list; on failure, targets already created
 * are removed before @p cb is invoked.
 *
 * @param queue   I/O queue that drives the operation.
 * @param target  Target string, see rawstor_object_create().
 * @param spec    Desired object metadata. Copied internally; does not need
 *                to stay valid after the call returns.
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_create
 */
int rawstor_object_create_async(
    RawIOQueue* queue, const char* target, const struct RawstorObjectSpec* spec,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously remove an object.
 *
 * Non-blocking variant of rawstor_object_remove(). The operation is driven
 * by @p queue; @p cb is invoked exactly once from the queue completion
 * context with 0 on success or a negative errno value on failure. If the
 * target contains multiple URIs, the object is removed from every backend
 * in the list even if some of them fail; the first error is reported.
 *
 * @param queue   I/O queue that drives the operation.
 * @param target  Target string, see rawstor_object_remove().
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_remove
 */
int rawstor_object_remove_async(
    RawIOQueue* queue, const char* target, int (*cb)(int result, void* data),
    void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Open an existing object for reading and/or writing.
 *
 * Given a target string (as defined in the Rawstor location/target syntax),
 * this function opens the specified object and returns an opaque handle that
 * can be used for subsequent read/write operations. The object must already
 * exist; otherwise, the function returns an error.
 *
 * If the target contains multiple URIs (mirroring or data locality), the
 * library selects the appropriate backend(s) according to the location
 * policy defined for that target.
 *
 * The returned RawstorObject handle must be closed with rawstor_object_close()
 * to release resources.
 *
 * @param target  Target string identifying the object to open, e.g.:
 *                - "ost://127.0.0.1:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "file:///var/rawstor/019cbfad-a389-7d42-a0f6-c29993ac8c00"
 *                - "ost://host1:9090/abc,ost://host2:9090/abc"  (mirroring)
 *                - "file:///data/abc,ost://host1:9090/abc"      (locality)
 * @param object  Pointer to a RawstorObject pointer that will receive the
 *                opaque handle on success. The caller must not modify the
 *                pointed-to memory directly. On error, *object is set to NULL.
 *
 * @return 0 on success, negative errno on error.
 * @retval 0        Object successfully opened.
 * @retval -EINVAL  Invalid target syntax (malformed URI, empty list, duplicate
 *                  URIs, mismatched UUIDs).
 * @retval -ENOENT  Object does not exist on any of the specified backends.
 * @retval -EIO     I/O error (network or filesystem).
 * @retval -EACCES  Permission denied.
 *
 * @see RawstorObject
 * @see rawstor_object_close
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_open(
    RawIOQueue* queue, const char* target, RawstorObject** object
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously open an existing object.
 *
 * Non-blocking variant of rawstor_object_open(). The operation is driven by
 * @p queue; @p cb is invoked exactly once from the queue completion context.
 * On success @p result is 0 and @p object is a valid handle that must be
 * closed with rawstor_object_close(). On failure @p result is a negative
 * errno value and @p object is NULL.
 *
 * @param queue   I/O queue that drives the operation and subsequent I/O on
 *                the opened object.
 * @param target  Target string, see rawstor_object_open().
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_open
 * @see rawstor_object_close
 */
int rawstor_object_open_async(
    RawIOQueue* queue, const char* target,
    int (*cb)(RawstorObject* object, int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Close an opened object and release associated resources.
 *
 * This function closes a RawstorObject handle previously obtained via
 * rawstor_object_open(). After closing, the handle becomes invalid and should
 * not be used further. Any pending write buffers are flushed to the backend(s)
 * before the handle is closed.
 *
 * @param object  Pointer to the RawstorObject handle to close. Cannot be NULL.
 *
 * @return 0 on success, negative errno on error.
 * @retval 0        Object successfully closed.
 * @retval -EIO     I/O error while flushing writes or finalizing metadata.
 *
 * @see rawstor_object_open
 */
int rawstor_object_close(RawstorObject* object) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve the UUID of an open object.
 *
 * Given an open RawstorObject handle, this function writes the object's
 * unique identifier (UUID) into the provided buffer. The UUID is the part
 * after the last slash in a target string (e.g., for target
 * "ost://host:9090/019cbfad-a389-7d42-a0f6-c29993ac8c00", the UUID is
 * "019cbfad-a389-7d42-a0f6-c29993ac8c00").
 *
 * If the buffer size is insufficient, the output is truncated but the
 * return value indicates the required buffer length (excluding the null
 * terminator), similar to snprintf().
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param buf     Output buffer that will receive the UUID string. Can be NULL
 *                if only the required buffer length is needed.
 * @param size    Size of the output buffer in bytes (including space for the
 *                terminating null byte). If size is 0, no data is written, but
 *                the required length is still returned.
 *
 * @return On success, returns the number of characters that would have been
 *         written to buf (excluding the terminating null byte). If this value
 *         is non‑negative but greater than or equal to size, the output was
 *         truncated.
 *
 * @see rawstor_object_open
 */
int rawstor_object_id(
    const RawstorObject* object, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Retrieve the list of location URIs for an open object.
 *
 * Given an open RawstorObject handle, this function writes a comma‑separated
 * list of location URIs (as defined in the Locations and Targets documentation)
 * into the provided buffer. These URIs represent the backend(s) where the
 * object is physically stored (e.g., OST servers, file system paths).
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
 * @param object  Open object handle obtained from rawstor_object_open().
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
 *         truncated.
 *
 * @see rawstor_object_id
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_location(
    const RawstorObject* object, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_object_preadv(
    RawstorObject* object, struct iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_object_pwritev(
    RawstorObject* object, const struct iovec* iov, unsigned int niov,
    size_t size, off_t offset, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Flush object data to stable storage.
 *
 * Asynchronously syncs previously completed writes of an open object to
 * stable storage on every backend in the target list. @p cb is invoked
 * exactly once from the queue completion context; a non-zero error means
 * that at least one backend failed to sync.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param cb      Completion callback; the size and result arguments are 0.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the operation was started, negative errno otherwise (in which
 *         case @p cb is never invoked).
 *
 * @see rawstor_object_pwrite
 */
int rawstor_object_flush(
    RawstorObject* object, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OBJECT_H
