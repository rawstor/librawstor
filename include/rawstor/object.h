/**
 * Copyright (C) 2025, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

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
    size_t size; /**< Size of the object in bytes. */
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
 * @brief Create a new empty object at the specified location.
 *
 * This function creates an object at the given location with the specified
 * metadata (e.g., size). Upon success, the target string of the newly created
 * object is written into the provided buffer. The target string follows the
 * format described in Locations and Targets documentation.
 *
 * @param location  Location string (e.g., "ost://host:port" or a
 *                  comma‑separated list). Specifies which backend(s) should
 *                  store the object.
 * @param spec      Pointer to a RawstorObjectSpec structure containing the
 *                  desired object metadata (e.g., size in bytes). The size
 *                  field must be set to the expected size of the object.
 * @param target    Output buffer that will receive the target string of the
 *                  created object (e.g., "ost://host:port/<uuid>").
 *                  Can not be NULL.
 * @param size      Size of the target buffer in bytes (including space for
 *                  the null terminator).
 *
 * @return On success, returns the number of characters that would have been
 *         written to target (excluding the terminating null byte), as with
 *         snprintf(). If this value is non‑negative but greater than or equal
 *         to size, the output was truncated.
 * @retval Negative value on error (e.g., -EINVAL for invalid location or spec,
 *         -ENOMEM, -EIO, etc.). The specific negative errno codes are
 *         implementation‑defined.
 *
 * @see RawstorObjectSpec
 * @see Locations and Targets:
 * https://github.com/rawstor/librawstor/blob/main/docs/locations_and_targets.md
 */
int rawstor_object_create(
    const char* location, const struct RawstorObjectSpec* spec, char* target,
    size_t size
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
    const char* target, RawstorObject** object
) RAWSTOR_NOEXCEPT;

/**
 * @brief Close an opened object and release associated resources.
 *
 * This function closes a RawstorObject handle previously obtained via
 * rawstor_object_open(). After closing, the handle becomes invalid and should
 * not be used further. Any pending write buffers are flushed to the backend(s)
 * before the handle is closed.
 *
 * @param object  Pointer to the RawstorObject handle to close. Can not be NULL.
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
 * @param buf     Output buffer that will receive the UUID string. Can not be
 *                NULL.
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

int rawstor_object_uris(
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
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_object_pwritev(
    RawstorObject* object, struct iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OBJECT_H
