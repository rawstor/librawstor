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

#include <stdbool.h>
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
 * retrieving existing object metadata (via rawstor_target_spec(), or the
 * deprecated rawstor_object_spec()) and for specifying parameters when
 * creating a new object (via rawstor_target_create(), or the deprecated
 * rawstor_object_create()/_create_at()).
 *
 * @see rawstor_target_spec
 * @see rawstor_target_create
 */
struct RawstorObjectSpec {
    uint64_t size; /**< Size of the object in bytes. */
};

/**
 * @brief Deprecated -- see rawstor_target_spec(). Fully synchronous (blocks
 *        the calling thread until the lookup completes), unlike
 *        rawstor_target_spec()'s caller-supplied-queue/callback shape.
 *
 * @deprecated Use rawstor_target_spec() instead.
 */
int rawstor_object_spec(
    const char* target, struct RawstorObjectSpec* spec
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_location_list(). Fully synchronous,
 *        unlike rawstor_location_list()'s caller-supplied-queue/callback
 *        shape.
 *
 * @deprecated Use rawstor_location_list() instead.
 */
int rawstor_object_list(
    const char* location, unsigned int limit, RawstorStringList** targets,
    RawstorPaginationToken* token
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_target_create(). Fully synchronous,
 *        unlike rawstor_target_create()'s caller-supplied-queue/callback
 *        shape.
 *
 * @deprecated Use rawstor_target_create() instead.
 */
int rawstor_object_create(
    const char* target, const struct RawstorObjectSpec* spec
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_location_create(). Fully synchronous
 *        (blocks until the create completes or the buffer-too-small check
 *        is done), unlike rawstor_location_create()'s
 *        caller-supplied-queue/callback shape; otherwise the same
 *        snprintf()-style return value convention.
 *
 * @deprecated Use rawstor_location_create() instead.
 */
int rawstor_object_create_at(
    const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_target_remove(). Fully synchronous,
 *        unlike rawstor_target_remove()'s caller-supplied-queue/callback
 *        shape.
 *
 * @deprecated Use rawstor_target_remove() instead.
 */
int rawstor_object_remove(const char* target) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_target_open(). Fully synchronous (blocks
 *        on @p queue until the open completes), unlike
 *        rawstor_target_open()'s callback-based completion.
 *
 * @deprecated Use rawstor_target_open() instead.
 */
int rawstor_object_open(
    RawIOQueue* queue, const char* target, RawstorObject** object
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_object_close2(). Fully synchronous (no
 *        callback, no queue parameter -- pumps the object's own queue
 *        internally until the close completes), unlike
 *        rawstor_object_close2()'s callback-based completion.
 *
 * @deprecated Use rawstor_object_close2() instead.
 */
int rawstor_object_close(RawstorObject* object) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_target_id(). Takes an open object handle
 *        rather than a target string, and round-trips through the object's
 *        own target (no behavioral difference otherwise -- both are purely
 *        syntactic).
 *
 * @deprecated Use rawstor_target_id() instead.
 */
int rawstor_object_id(
    const RawstorObject* object, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_target_location(). Takes an open object
 *        handle rather than a target string; otherwise identical.
 *
 * @deprecated Use rawstor_target_location() instead.
 */
int rawstor_object_location(
    const RawstorObject* object, char* buf, size_t size
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated completion callback shape for rawstor_object_pread()/
 *        _preadv()/_pwrite()/_pwritev()/_flush() below. Superseded by the
 *        collapsed inline shape used by rawstor_object_pread2()/_preadv2()/
 *        _pwrite2()/_pwritev2()/_flush2() (which also drops the redundant
 *        @p object/@p size parameters every caller either ignored or
 *        already had in scope).
 *
 * @param object  The same RawstorObject handle passed to the initiating
 *                function.
 * @param size    The size requested by the initiating call. For
 *                rawstor_object_flush(), always 0.
 * @param result  Number of bytes actually transferred.
 * @param error   Error code from the operation. Zero indicates success; a
 *                non-zero value is a positive errno.
 * @param data    User-defined context pointer passed unchanged from the
 *                initiating function.
 *
 * @return        Zero on success. A negative errno value signals an error
 *                back into the I/O completion machinery.
 *
 * @deprecated    Use the collapsed rawstor_object_pread2()-style shape
 *                instead.
 */
typedef int(RawstorCallback)(
    RawstorObject* object, size_t size, size_t result, int error, void* data
);

/**
 * @brief Deprecated -- see rawstor_object_pread2(). Same operation, old
 *        RawstorCallback shape.
 *
 * @deprecated Use rawstor_object_pread2() instead.
 */
int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/** @deprecated Use rawstor_object_preadv2() instead. See
 * rawstor_object_pread()'s note. */
int rawstor_object_preadv(
    RawstorObject* object, struct iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Deprecated -- see rawstor_object_pwrite2(). Same operation, old
 *        RawstorCallback shape; `sync` is unchanged.
 *
 * @deprecated Use rawstor_object_pwrite2() instead.
 */
int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    bool sync, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/** @deprecated Use rawstor_object_pwritev2() instead. See
 * rawstor_object_pwrite()'s note. */
int rawstor_object_pwritev(
    RawstorObject* object, const struct iovec* iov, unsigned int niov,
    size_t size, off_t offset, bool sync, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/** @deprecated Use rawstor_object_flush2() instead. See
 * rawstor_object_pread()'s note. */
int rawstor_object_flush(
    RawstorObject* object, RawstorCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously close an opened object and release associated
 *        resources.
 *
 * This function closes a RawstorObject handle previously obtained via
 * rawstor_target_open(). After this function is called, the handle must not
 * be used for any further operation (including a second close), even while
 * the close is still in flight. Any pending write buffers are flushed to
 * the backend(s) before the close completes.
 *
 * This function returns immediately; the actual result is reported via
 * @p cb once the operation completes. @p object itself is freed as part of
 * completing the close, before @p cb is invoked -- after calling this
 * function, @p object must not be referenced again for any purpose.
 *
 * @param object  Pointer to the RawstorObject handle to close. Cannot be
 *                NULL.
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure (e.g. @c -EIO if flushing writes or finalizing
 *                  metadata failed).
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the close was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual close result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_target_open
 */
int rawstor_object_close2(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Shared completion callback shape for rawstor_object_pread2()
 *        below and _preadv2()/_pwrite2()/_pwritev2() further down (see
 *        rawstor_object_flush2() for its own, distinct callback shape).
 *
 * @param result  Number of bytes actually transferred -- for read/write
 *                operations: may be less than the size requested by the
 *                initiating call, on a short read/write.
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

/**
 * @brief Asynchronously read data from an object at a given offset.
 *
 * Queues a read of @p size bytes starting at @p offset into @p buf. This
 * function returns immediately; the actual result is reported via @p cb once
 * the operation completes.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param buf     Destination buffer for the read data. Must remain valid
 *                until @p cb is invoked.
 * @param size    Number of bytes to read.
 * @param offset  Byte offset within the object to read from.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the read was successfully queued; negative errno on immediate
 *         failure (in which case @p cb is never invoked). The actual read
 *         result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_preadv2
 * @see rawstor_object_pwrite2
 */
int rawstor_object_pread2(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously read data from an object into multiple buffers
 *        (scatter-gather).
 *
 * Vectored equivalent of rawstor_object_pread2(): reads @p size bytes total
 * starting at @p offset, scattered across the buffers described by @p iov.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param iov     Array of buffers to scatter the read data into. Must remain
 *                valid until @p cb is invoked.
 * @param niov    Number of entries in @p iov.
 * @param size    Total number of bytes to read, summed across all @p iov
 *                entries.
 * @param offset  Byte offset within the object to read from.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the read was successfully queued; negative errno on immediate
 *         failure (in which case @p cb is never invoked). The actual read
 *         result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pread2
 * @see rawstor_object_pwritev2
 */
int rawstor_object_preadv2(
    RawstorObject* object, struct iovec* iov, unsigned int niov, size_t size,
    off_t offset, int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously write data to an object at a given offset.
 *
 * Queues a write of @p size bytes from @p buf starting at @p offset. This
 * function returns immediately; the actual result is reported via @p cb once
 * the operation completes.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param buf     Source buffer to write from. Must remain valid until @p cb
 *                is invoked.
 * @param size    Number of bytes to write.
 * @param offset  Byte offset within the object to write to.
 * @param sync    If true, the write is durable on stable storage by the time
 *                @p cb reports success (equivalent to O_DSYNC per-call). If
 *                false, durability is only guaranteed after a subsequent
 *                rawstor_object_flush2() whose own completion callback fires
 *                after this write's.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual write result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pwritev2
 * @see rawstor_object_flush2
 * @see rawstor_object_pread2
 */
int rawstor_object_pwrite2(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    bool sync, int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously write data to an object from multiple buffers
 *        (scatter-gather).
 *
 * Vectored equivalent of rawstor_object_pwrite2(): writes @p size bytes
 * total starting at @p offset, gathered from the buffers described by
 * @p iov.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param iov     Array of buffers to gather the write data from. Must
 *                remain valid until @p cb is invoked.
 * @param niov    Number of entries in @p iov.
 * @param size    Total number of bytes to write, summed across all @p iov
 *                entries.
 * @param offset  Byte offset within the object to write to.
 * @param sync    If true, the write is durable on stable storage by the time
 *                @p cb reports success (equivalent to O_DSYNC per-call). If
 *                false, durability is only guaranteed after a subsequent
 *                rawstor_object_flush2() whose own completion callback fires
 *                after this write's.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual write result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pwrite2
 * @see rawstor_object_flush2
 * @see rawstor_object_preadv2
 */
int rawstor_object_pwritev2(
    RawstorObject* object, const struct iovec* iov, unsigned int niov,
    size_t size, off_t offset, bool sync,
    int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Flush an object's previously written data to stable storage.
 *
 * A durability barrier: once @p cb reports success, every write whose own
 * completion callback had already fired before this function was called is
 * guaranteed durable.
 *
 * This does **not** cover writes that are merely queued but still in flight
 * (i.e. rawstor_object_pwrite2()/pwritev() was called but its own @p cb has
 * not fired yet) at the time rawstor_object_flush2() is called -- wait for
 * their completion first if they need to be covered by this flush.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure. There's nothing else to report -- unlike
 *                  rawstor_object_pread2()/_preadv2()/_pwrite2()/
 *                  _pwritev2()'s shared callback shape, this one is
 *                  flush2()'s own.
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the flush was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual flush result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pwrite2
 * @see rawstor_object_pwritev2
 */
int rawstor_object_flush2(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OBJECT_H
