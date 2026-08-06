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
struct RawstorObjectSpec {
    uint64_t size; /**< Size of the object in bytes. */
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
