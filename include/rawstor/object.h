/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

#include <rawstor/list.h>
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
/** Chunk member kinds (rawstor_docs/Mds.md, chunk_meta.member_kind). */
#define RAWSTOR_MEMBER_DATA 0u
#define RAWSTOR_MEMBER_WITNESS 1u /* metadata-only quorum member; stage 3 */

struct RawstorObjectSpec {
    uint64_t size; /**< Size of the object in bytes. */

    /*
     * Volume policy, mds:// targets only (rawstor_docs/Mds.md). Zeros are
     * defaults that degenerate to a single-chunk, single-copy volume -
     * which behaves exactly like a plain object.
     */
    uint64_t chunk_size;    /**< Power of two; 0 = one chunk spans the
                                 volume. */
    uint64_t stripe_width;  /**< K; 0 = spread every chunk, 1 =
                                 volume-local. */
    uint8_t width;          /**< Copies per chunk; 0 = 1. */
    uint8_t failure_domain; /**< RAWSTOR_VOL_DOMAIN_*; default server. */

    /*
     * Placement identity of a chunk object (rawstor_docs/Mds.md,
     * chunk_meta): stamped at create by the volume layer, immutable
     * afterwards (set_state never touches it), the source for the map
     * reconstruct scan. An all-zero volume_id is a standalone object.
     */
    uint8_t member_kind;    /**< RAWSTOR_MEMBER_*. */
    uint8_t volume_id[16];  /**< Parent volume; all-zero = standalone. */
    uint64_t logical_index; /**< Chunk position within the volume. */
    uint64_t snap_version;  /**< snap_id this copy belongs to; 0 = live. */
};

/**
 * @brief Generic callback for asynchronous object I/O operations.
 *
 * Used by rawstor_object_pread(), rawstor_object_preadv(),
 * rawstor_object_pwrite(), rawstor_object_pwritev() and
 * rawstor_object_flush() to report completion of the requested operation.
 *
 * @param object  The same RawstorObject handle passed to the initiating
 *                function.
 * @param size    The size requested by the initiating call (the @p size
 *                argument passed to it). For rawstor_object_flush(), always
 *                0.
 * @param result  Number of bytes actually transferred.
 *                - For read/write operations: may be less than @p size on a
 *                  short read/write.
 *                - For rawstor_object_flush(): always 0.
 * @param error   Error code from the operation. Zero indicates successful
 *                completion; a non-zero value is a positive errno.
 * @param data    User-defined context pointer passed unchanged from the
 *                initiating function.
 *
 * @return        Zero on success. A negative errno value signals an error
 *                back into the I/O completion machinery.
 *
 * @note          The callback may be invoked from an I/O completion context.
 *                Avoid blocking operations inside the callback.
 */

typedef int(RawstorCallback)(
    RawstorObject* object, size_t size, size_t result, int error, void* data
);

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
 * object copy (see docs/mirroring.md). A sync_id of 0 marks a blank copy
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

    /*
     * Placement identity (see RawstorObjectSpec) plus the volume policy
     * recorded on the chunk: written at create, immutable, ignored by
     * rawstor_object_set_state() - the stored values always win.
     */
    uint8_t member_kind;
    uint8_t width; /**< Redundancy: copies per chunk. */
    uint8_t volume_id[16];
    uint64_t logical_index;
    uint64_t chunk_size;
    uint64_t snap_version;
};

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
 * @brief List objects stored at the given location.
 *
 * This function retrieves a list of object identifiers (full target strings)
 * stored at the specified @p location. The location must be a comma separated
 * list of valid backend URI as described in the Locations and Targets
 * documentation. The function supports pagination via the @p token parameter,
 * allowing the caller to iterate over large sets of objects.
 *
 * The objects are returned in lexicographic order by their UUID. The
 * @p limit parameter restricts the maximum number of objects returned in a
 * single call. If @p limit is 0, the backend chooses an appropriate number
 * of objects to return. The backend may enforce its own maximum limit
 * (e.g., via the @c RAWSTOR_OPTS_LIST_LIMIT environment variable on the
 * server side) that caps the actual number of strings returned, regardless
 * of the @p limit value specified by the caller. If the number of objects
 * available exceeds the effective limit (either specified by the caller or
 * chosen by the backend), the function fills the @p token with an opaque
 * pagination token that must be passed in the subsequent call to continue
 * iteration. When the end of the list is reached, the token is set to an
 * empty state (as determined by @ref rawstor_pagination_token_empty).
 *
 * The caller is responsible for freeing the returned string list using
 * @ref rawstor_string_list_delete. The pagination token is a plain structure
 * of fixed size (16 bytes) and does not require explicit deallocation;
 * it should be zero‑initialized before the first call.
 *
 * @param location  Location string specifying the backend and endpoint
 *                  (e.g., "ost://host:port" or "file:///path"). Must not be
 *                  NULL and must be a valid location as per the library's
 *                  format. The behaviour is identical to the @p location
 *                  parameter of @ref rawstor_object_create_at.
 * @param limit     Maximum number of objects to return in this call. If 0, the
 *                  backend chooses the number of objects to return. The actual
 *                  number of objects returned may also be limited by the
 *                  backend's internal configuration (e.g., the
 *                  @c RAWSTOR_OPTS_LIST_LIMIT environment variable on the
 *                  server side).
 * @param targets   Output parameter. On success, a pointer to a newly
 *                  allocated @ref RawstorStringList is stored here. The list
 *                  contains full target strings (e.g.,
 *                  "ost://host:port/<uuid>") for each object. The caller must
 *                  destroy the list using @ref rawstor_string_list_delete when
 *                  it is no longer needed. The list is owned by the caller
 *                  after a successful return. On error, the content of this
 *                  parameter is undefined.
 * @param token     Input/Output parameter for pagination. On the first call,
 *                  the caller must zero‑initialize the structure (e.g.,
 *                  `RawstorPaginationToken token = {};`). On success, if more
 *                  objects are available, the function fills the token with an
 *                  opaque value; otherwise, the token is set to an empty state
 *                  (checkable via @ref rawstor_pagination_token_empty). The
 *                  caller must pass the same token structure (with the value
 *                  returned from the previous call) in subsequent calls to
 *                  retrieve the next page. The token is opaque and must not be
 *                  modified by the caller.
 *
 * @return 0 on success, negative errno on error.
 * @retval 0         Success. The @p targets list and @p token are valid.
 * @retval -EINVAL   Invalid input: @p location is NULL or malformed.
 * @retval -ENOMEM   Memory allocation failed (for the list).
 * @retval -ENOENT   The specified @p location does not exist or is unreachable.
 * @retval -EIO      I/O error while reading the backend.
 * @retval -EACCES   Permission denied for the specified location.
 *
 * @note If an invalid or corrupted token is passed (e.g., from a previous
 *       session or after modifications to the storage), the behaviour is
 *       undefined; the function may return incomplete or inconsistent results.
 *
 * @note The function may return a partial list even if an error occurs
 *       (e.g., if the backend becomes unavailable mid‑iteration); however,
 *       in such cases a negative error code is returned and the contents of
 *       @p targets and @p token are unspecified. Callers should not rely on
 *       partial data when an error is returned.
 *
 * @note Objects inserted into the already‑retrieved portion of the list
 *       between calls will not be visible in subsequent iterations; the
 *       token‑based pagination ensures consistency within the current
 *       iteration session.
 *
 * @see rawstor_string_list_delete
 * @see rawstor_pagination_token_empty
 * @see rawstor_object_create_at
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 *
 * @par Example: Iterating over all objects
 * @code
 * RawstorPaginationToken token = {}; // zero‑initialized
 *
 * do {
 *     RawstorStringList* page;
 *     int ret = rawstor_object_list("ost://localhost:9090", 0, &page, &token);
 *     if (ret < 0) {
 *         // handle error
 *         break;
 *     }
 *     for (const char** it = rawstor_string_list_iter(page); it != NULL;
 *          it = rawstor_string_list_next(it)) {
 *         // Process strings in list using *it.
 *     }
 *     rawstor_string_list_delete(page);
 * } while (!rawstor_pagination_token_empty(&token));
 * @endcode
 */
int rawstor_object_list(
    const char* location, unsigned int limit, RawstorStringList** targets,
    RawstorPaginationToken* token
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
/**
 * @brief One stored object of a location listing.
 *
 * @see rawstor_object_list
 */
struct RawstorObjectListEntry {
    uint8_t obj_id[16]; /**< Physical object id. */
    struct RawstorObjectMeta meta;
};

/**
 * @brief Enumerate the objects stored at a location.
 *
 * Lists every object of a single backend location (not a target: no UUID,
 * no comma-separated lists) together with its metadata — the source of the
 * MDS map reconstruct scan (rawstor_docs/Mds.md, "Reconstruct / DR") over
 * CMD_LIST_CHUNKS. Objects whose metadata cannot be read are skipped with
 * an error logged: a reconstruct scan must salvage the readable copies, and
 * every skipped copy is covered by its mirrors.
 *
 * @param location  Location string (e.g. "file:///var/rawstor",
 *                  "ost://127.0.0.1:8080").
 * @param entries   On success *entries points to a malloc'd array that the
 *                  caller releases with free(). NULL when *nentries is 0.
 * @param nentries  Number of entries returned.
 *
 * @return 0 on success, negative errno otherwise.
 *
 * @see rawstor_object_meta
 */
int rawstor_object_list_chunks(
    const char* location, struct RawstorObjectListEntry** entries,
    size_t* nentries
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously enumerate the objects stored at a location.
 *
 * Non-blocking variant of rawstor_object_list(). The operation is driven by
 * @p queue; @p cb is invoked exactly once from the queue completion context
 * with 0 on success or a negative errno value on failure. On success
 * *entries and *nentries are filled before @p cb is invoked; both must stay
 * valid until then. The caller releases *entries with free().
 *
 * @return 0 if the operation was started, negative errno otherwise (in
 *         which case @p cb is never invoked).
 *
 * @see rawstor_object_list
 */
int rawstor_object_list_chunks_async(
    RawIOQueue* queue, const char* location,
    struct RawstorObjectListEntry** entries, size_t* nentries,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawstor_object_set_state_async(
    RawIOQueue* queue, const char* target, const struct RawstorObjectMeta* meta,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Take a native CoW snapshot of an object as version @p snap_id.
 *
 * The snapshot is taken on every backend listed in @p target; the first
 * error encountered is returned, the remaining backends are still
 * attempted. The caller owns crash consistency: all acknowledged writes
 * must be flushed before the call (rawstor_docs/Mds.md, "Snapshots").
 *
 * @param target   Target string, see rawstor_object_spec().
 * @param snap_id  Version id; must not be 0 (0 is the live version).
 *
 * @return 0 on success, negative errno otherwise.
 * @retval -ENOTSUP  A backend has no CoW (file://, classic LVM) — no
 *                   fallback copies are made behind the caller's back.
 */
int rawstor_object_snapshot(
    const char* target, uint64_t snap_id
) RAWSTOR_NOEXCEPT;

/**
 * @brief Non-blocking variant of rawstor_object_snapshot().
 *
 * @return 0 if the operation was started, negative errno otherwise (in
 *         which case @p cb is never invoked).
 */
int rawstor_object_snapshot_async(
    RawIOQueue* queue, const char* target, uint64_t snap_id,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Destroy snapshot version @p snap_id of an object.
 *
 * Fan-out semantics as rawstor_object_snapshot().
 *
 * @return 0 on success, negative errno otherwise.
 */
int rawstor_object_snap_remove(
    const char* target, uint64_t snap_id
) RAWSTOR_NOEXCEPT;

/**
 * @brief Non-blocking variant of rawstor_object_snap_remove().
 *
 * @return 0 if the operation was started, negative errno otherwise (in
 *         which case @p cb is never invoked).
 */
int rawstor_object_snap_remove_async(
    RawIOQueue* queue, const char* target, uint64_t snap_id,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Snapshot an MDS-backed volume.
 *
 * Two-phase, per rawstor_docs/Mds.md "Snapshots": the MDS reserves the
 * snap_id, every chunk is opened (a regular mirrored open — it
 * establishes the IN-SYNC member set), flushed and CoW-snapshotted on
 * its IN-SYNC members, and the participants are registered. The caller
 * guarantees no concurrent writer. The snapshot is later read through
 * the regular open with an "@<snap_id>" target suffix
 * (mds://host:port/<volume_id>@<snap_id>) and is immutable.
 *
 * @param target   A single mds:// volume target.
 * @param snap_id  Filled with the created snapshot id on success.
 *
 * @return 0 on success, negative errno otherwise.
 * @retval -ENOTSUP  A chunk member has no CoW backend (file://, classic
 *                   LVM) — nothing is registered.
 */
int rawstor_volume_snapshot(
    const char* target, uint64_t* snap_id
) RAWSTOR_NOEXCEPT;

/**
 * @brief Non-blocking variant of rawstor_volume_snapshot().
 *
 * @return 0 if the operation was started, negative errno otherwise (in
 *         which case @p cb is never invoked).
 */
int rawstor_volume_snapshot_async(
    RawIOQueue* queue, const char* target, uint64_t* snap_id,
    int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Remove a volume snapshot.
 *
 * The MDS unregisters the snapshot first (no new readers), then the
 * per-chunk CoWs are destroyed on the recorded members. A crash in
 * between leaves unregistered backend snapshots — garbage reconciled by
 * the reconstruct scan, never a dangling registration.
 *
 * @return 0 on success, negative errno otherwise.
 */
int rawstor_volume_snap_remove(
    const char* target, uint64_t snap_id
) RAWSTOR_NOEXCEPT;

/**
 * @brief Non-blocking variant of rawstor_volume_snap_remove().
 *
 * @return 0 if the operation was started, negative errno otherwise (in
 *         which case @p cb is never invoked).
 */
int rawstor_volume_snap_remove_async(
    RawIOQueue* queue, const char* target, uint64_t snap_id,
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
 * @brief Cleanly close an opened object.
 *
 * Flushes completed writes to stable storage, durably marks the in-sync
 * copies CLEAN and releases the handle. @p cb is invoked exactly once from
 * the queue completion context; the handle is invalid once this function
 * returns 0, even if @p cb later reports an error. On errors the affected
 * copies are left DIRTY (the safe direction: they will be treated as
 * potentially divergent on the next open) and the first error is reported.
 *
 * There must be no I/O in flight on the object when this is called.
 *
 * Note that rawstor_object_close() performs an *unclean* close: it releases
 * the handle without flushing or marking the copies CLEAN.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param cb      Completion callback.
 * @param data    Opaque pointer passed to @p cb.
 *
 * @return 0 if the close was started, negative errno otherwise (in which
 *         case @p cb is never invoked and the handle stays valid).
 *
 * @see rawstor_object_close
 */
int rawstor_object_close_async(
    RawstorObject* object, int (*cb)(int result, void* data), void* data
) RAWSTOR_NOEXCEPT;

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

/**
 * @brief Asynchronously read data from an object at a given offset.
 *
 * Queues a read of @p size bytes starting at @p offset into @p buf. This
 * function returns immediately; the actual result is reported via @p cb once
 * the operation completes.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param buf     Destination buffer for the read data. Must remain valid
 *                until @p cb is invoked.
 * @param size    Number of bytes to read.
 * @param offset  Byte offset within the object to read from.
 * @param cb      Callback invoked on completion. See RawstorCallback.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the read was successfully queued; negative errno on immediate
 *         failure (in which case @p cb is never invoked). The actual read
 *         result (success or failure) is delivered via @p cb.
 *
 * @see RawstorCallback
 * @see rawstor_object_preadv
 * @see rawstor_object_pwrite
 */
int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously read data from an object into multiple buffers
 *        (scatter-gather).
 *
 * Vectored equivalent of rawstor_object_pread(): reads @p size bytes total
 * starting at @p offset, scattered across the buffers described by @p iov.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param iov     Array of buffers to scatter the read data into. Must remain
 *                valid until @p cb is invoked.
 * @param niov    Number of entries in @p iov.
 * @param size    Total number of bytes to read, summed across all @p iov
 *                entries.
 * @param offset  Byte offset within the object to read from.
 * @param cb      Callback invoked on completion. See RawstorCallback.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the read was successfully queued; negative errno on immediate
 *         failure (in which case @p cb is never invoked). The actual read
 *         result (success or failure) is delivered via @p cb.
 *
 * @see RawstorCallback
 * @see rawstor_object_pread
 * @see rawstor_object_pwritev
 */
int rawstor_object_preadv(
    RawstorObject* object, struct iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously write data to an object at a given offset.
 *
 * Queues a write of @p size bytes from @p buf starting at @p offset. This
 * function returns immediately; the actual result is reported via @p cb once
 * the operation completes.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param buf     Source buffer to write from. Must remain valid until @p cb
 *                is invoked.
 * @param size    Number of bytes to write.
 * @param offset  Byte offset within the object to write to.
 * @param sync    If true, the write is durable on stable storage by the time
 *                @p cb reports success (equivalent to O_DSYNC per-call). If
 *                false, durability is only guaranteed after a subsequent
 *                rawstor_object_flush() whose own completion callback fires
 *                after this write's.
 * @param cb      Callback invoked on completion. See RawstorCallback.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual write result (success or failure) is delivered via @p cb.
 *
 * @see RawstorCallback
 * @see rawstor_object_pwritev
 * @see rawstor_object_flush
 * @see rawstor_object_pread
 */
int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    bool sync, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously write data to an object from multiple buffers
 *        (scatter-gather).
 *
 * Vectored equivalent of rawstor_object_pwrite(): writes @p size bytes
 * total starting at @p offset, gathered from the buffers described by
 * @p iov.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param iov     Array of buffers to gather the write data from. Must
 *                remain valid until @p cb is invoked.
 * @param niov    Number of entries in @p iov.
 * @param size    Total number of bytes to write, summed across all @p iov
 *                entries.
 * @param offset  Byte offset within the object to write to.
 * @param sync    If true, the write is durable on stable storage by the time
 *                @p cb reports success (equivalent to O_DSYNC per-call). If
 *                false, durability is only guaranteed after a subsequent
 *                rawstor_object_flush() whose own completion callback fires
 *                after this write's.
 * @param cb      Callback invoked on completion. See RawstorCallback.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual write result (success or failure) is delivered via @p cb.
 *
 * @see RawstorCallback
 * @see rawstor_object_pwrite
 * @see rawstor_object_flush
 * @see rawstor_object_preadv
 */
int rawstor_object_pwritev(
    RawstorObject* object, const struct iovec* iov, unsigned int niov,
    size_t size, off_t offset, bool sync, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Flush an object's previously written data to stable storage.
 *
 * A durability barrier: once @p cb reports success, every write whose own
 * completion callback had already fired before this function was called is
 * guaranteed durable.
 *
 * This does **not** cover writes that are merely queued but still in flight
 * (i.e. rawstor_object_pwrite()/pwritev() was called but its own @p cb has
 * not fired yet) at the time rawstor_object_flush() is called -- wait for
 * their completion first if they need to be covered by this flush.
 *
 * @param object  Open object handle obtained from rawstor_object_open().
 * @param cb      Callback invoked on completion. See RawstorCallback.
 *                Always invoked with `size = 0, result = 0`.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the flush was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual flush result (success or failure) is delivered via @p cb.
 *
 * @see RawstorCallback
 * @see rawstor_object_pwrite
 * @see rawstor_object_pwritev
 */
int rawstor_object_flush(
    RawstorObject* object, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OBJECT_H
