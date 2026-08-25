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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Asynchronously retrieve metadata about a stored object.
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
/**
 * @brief Object metadata structure. See RawstorObjectSpec's own doc
 *        comment in <rawstor/object.h> (its canonical home -- RawstorObject
 *        lives there too, and every old-API compat function that predates
 *        target.h/location.h needs it reachable via a plain
 *        `#include <rawstor/object.h>`).
 */

int rawstor_target_spec(
    RawIOQueue* queue, const char* target, struct RawstorObjectSpec* spec,
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
 *                  desired object metadata (e.g., size in bytes). The size
 *                  field must be set to the expected size of the object. Only
 *                  read while this call is being queued -- need not stay
 *                  valid until @p cb runs.
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure (e.g. @c -EINVAL for invalid target or spec,
 *                    @c -ENOMEM, @c -EIO, etc; implementation‑defined beyond
 *                    that).
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
 * rawstor_object_close2() to release resources.
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
 * @see rawstor_object_close2
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
