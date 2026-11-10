/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

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
int rawstor_object_close(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously close an object whose writer did not finish
 *        cleanly.
 *
 * Same as rawstor_object_close(), except that the object's writer is not
 * declared done: a stored copy written through @p object that is DIRTY
 * becomes LOST instead of CLEAN (docs/mirroring.md, "DIRTY, CLEAN and
 * LOST"). For a server relaying a remote writer's session -- e.g.
 * rawstor-ost when the connection drops without the writer's LEAVE.
 *
 * @return 0 if the close was queued; negative errno on immediate failure
 *         (in which case @p cb is never invoked).
 */
int rawstor_object_abandon(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Shared completion callback shape for rawstor_object_pread()
 *        below and _preadv()/_pwrite()/_pwritev() further down (see
 *        rawstor_object_flush() for its own, distinct callback shape).
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
 * @see rawstor_object_preadv
 * @see rawstor_object_pwrite
 */
int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, uint64_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously read data from an object into multiple buffers
 *        (scatter-gather).
 *
 * Vectored equivalent of rawstor_object_pread(): reads @p size bytes total
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
 * @see rawstor_object_pread
 * @see rawstor_object_pwritev
 */
int rawstor_object_preadv(
    RawstorObject* object, struct iovec* iov, unsigned int niov, size_t size,
    uint64_t offset, int (*cb)(size_t result, int error, void* data), void* data
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
 *                rawstor_object_flush() call issued after this one --
 *                flush() itself waits for this write to complete, so @p cb
 *                need not have fired yet by the time flush() is called.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual write result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pwritev
 * @see rawstor_object_flush
 * @see rawstor_object_pread
 */
int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, uint64_t offset,
    bool sync, int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously write data to an object from multiple buffers
 *        (scatter-gather).
 *
 * Vectored equivalent of rawstor_object_pwrite(): writes @p size bytes
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
 *                rawstor_object_flush() call issued after this one --
 *                flush() itself waits for this write to complete, so @p cb
 *                need not have fired yet by the time flush() is called.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual write result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pwrite
 * @see rawstor_object_flush
 * @see rawstor_object_preadv
 */
int rawstor_object_pwritev(
    RawstorObject* object, const struct iovec* iov, unsigned int niov,
    size_t size, uint64_t offset, bool sync,
    int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Hint that a byte range is no longer in use.
 *
 * Advisory only: lets the backend reclaim the underlying storage for
 * [@p offset, @p offset + @p size) if it can, but never guarantees the
 * range reads back as zero afterward, or that anything was reclaimed at
 * all -- unlike rawstor_object_write_zeroes() below. This function returns
 * immediately; the actual result is reported via @p cb once the operation
 * completes.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param size    Number of bytes to discard.
 * @param offset  Byte offset within the object to discard from.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the discard was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual discard result (success or failure) is delivered via
 *         @p cb.
 *
 * @see rawstor_object_write_zeroes
 * @see rawstor_object_pwrite
 */
int rawstor_object_discard(
    RawstorObject* object, size_t size, uint64_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Zero a byte range without transferring zero bytes over the wire.
 *
 * Queues zeroing of [@p offset, @p offset + @p size). Unlike
 * rawstor_object_discard() above, the range is guaranteed to read back as
 * zero once @p cb reports success. This function returns immediately; the
 * actual result is reported via @p cb once the operation completes.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param size    Number of bytes to zero.
 * @param offset  Byte offset within the object to zero from.
 * @param unmap   If true, hints that the backend may (not must) also
 *                deallocate the underlying storage for the zeroed range --
 *                same meaning as virtio-blk's
 *                VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP. If false, the backend
 *                must still leave the range allocated.
 * @param sync    If true, the zeroed range is durable on stable storage by
 *                the time @p cb reports success (equivalent to O_DSYNC
 *                per-call). If false, durability is only guaranteed after a
 *                subsequent rawstor_object_flush() -- same meaning as
 *                rawstor_object_pwrite()'s own @p sync.
 * @param cb      Callback invoked on completion.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the write-zeroes was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_discard
 * @see rawstor_object_pwrite
 */
int rawstor_object_write_zeroes(
    RawstorObject* object, size_t size, uint64_t offset, bool unmap, bool sync,
    int (*cb)(size_t result, int error, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Flush an object's previously written data to stable storage.
 *
 * A durability barrier: once @p cb reports success, every
 * rawstor_object_pwrite()/pwritev() call issued before this function was
 * called is guaranteed durable -- including one still in flight (its own
 * @p cb not fired yet) at the time this function is called; flush() waits
 * for it internally. A write issued concurrently with, or after, this call
 * isn't covered, same as fsync() never covering a write that hasn't
 * happened yet.
 *
 * @param object  Open object handle obtained from rawstor_target_open().
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure. There's nothing else to report -- unlike
 *                  rawstor_object_pread()/_preadv()/_pwrite()/_pwritev()'s
 *                  shared callback shape, this one is flush()'s own.
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the flush was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual flush result (success or failure) is delivered via @p cb.
 *
 * @see rawstor_object_pwrite
 * @see rawstor_object_pwritev
 */
int rawstor_object_flush(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/** Size of the user data a chunk keeps in its configuration register. */
#define RAWSTOR_OBJECT_USER_DATA_SIZE 256

/**
 * @brief Asynchronously read the user data of the chunk that holds @p offset.
 *
 * Every chunk's configuration register carries RAWSTOR_OBJECT_USER_DATA_SIZE
 * opaque bytes for the application, replicated on all the chunk's members and
 * zero until first set. The read goes through the register, so the answer is
 * the value a majority of the members decided -- another writer's latest
 * change included -- not what this process saw last.
 *
 * A change of the user data moves the chunk's configuration epoch. Writes
 * carry the epoch of the configuration they were issued under, and a member
 * refuses one below its own with @c -ESTALE: a writer that kept using the
 * chunk after another one replaced the user data is stopped at its next write
 * (and takes the new value over, for any I/O it issues afterwards). That is
 * what makes the user data usable as a lock held by one writer at a time, a
 * leader's identity and the like.
 *
 * @param object  Open object handle obtained from rawstor_target_open(),
 *                opened for writing: the read is a decision of the register.
 * @param offset  Byte offset within the object; selects the chunk the same
 *                way I/O offsets do. It must lie within the object.
 * @param value   Receives RAWSTOR_OBJECT_USER_DATA_SIZE bytes. Must remain
 *                valid until @p cb is invoked.
 * @param epoch   Receives the configuration epoch the value was decided at;
 *                may be NULL. Must remain valid until @p cb is invoked.
 * @param cb      Callback invoked on completion.
 *                - @p result is zero on success, or a negative errno on
 *                  failure (@c -EROFS for an object opened
 *                  RAWSTOR_READONLY, @c -EINVAL for an offset outside the
 *                  object, @c -EIO when no majority of the members could be
 *                  reached).
 *                - @p data is the same pointer passed as @p data below.
 *                - Return zero on success. A negative errno value signals an
 *                  error back into the I/O completion machinery.
 * @param data    User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the read was successfully queued; negative errno on immediate
 *         failure (in which case @p cb is never invoked).
 *
 * @see rawstor_object_user_data_cas
 */
int rawstor_object_user_data_get(
    RawstorObject* object, uint64_t offset, uint8_t* value, uint64_t* epoch,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously set the user data of the chunk that holds @p offset
 *        if it is @p expected (compare and swap).
 *
 * The register changes only when it holds @p expected at the moment a
 * majority of the members decide the change; otherwise nothing is written.
 * Concurrent callers, in this process or others, are ordered by the
 * register: at most one of several that expect the same value succeeds, and
 * the others learn the value that won. See rawstor_object_user_data_get()
 * for what the epoch makes of a change.
 *
 * Setting the value the register already holds (@p expected equal to
 * @p desired) writes nothing the other writers could tell apart and leaves
 * the epoch where it is; the call still goes through the register, so it
 * confirms the value is the one a majority holds.
 *
 * @param object    Open object handle obtained from rawstor_target_open(),
 *                  opened for writing.
 * @param offset    Byte offset within the object; selects the chunk. It must
 *                  lie within the object.
 * @param expected  RAWSTOR_OBJECT_USER_DATA_SIZE bytes the register must
 *                  hold. Must remain valid until @p cb is invoked.
 * @param desired   RAWSTOR_OBJECT_USER_DATA_SIZE bytes to set. Must remain
 *                  valid until @p cb is invoked.
 * @param current   Receives the value the register holds after the call:
 *                  @p desired on success, the value that was there when it
 *                  did not match. Must remain valid until @p cb is invoked.
 * @param epoch     Receives the epoch of that value; may be NULL. Must
 *                  remain valid until @p cb is invoked.
 * @param cb        Callback invoked on completion.
 *                  - @p result is 1 if the value was set, 0 if the register
 *                    held another one (not an I/O error), or a negative
 *                    errno on failure, as for rawstor_object_user_data_get().
 *                  - @p data is the same pointer passed as @p data below.
 *                  - Return zero on success. A negative errno value signals
 *                    an error back into the I/O completion machinery.
 * @param data      User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the change was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked).
 *
 * @see rawstor_object_user_data_get
 */
int rawstor_object_user_data_cas(
    RawstorObject* object, uint64_t offset, const uint8_t* expected,
    const uint8_t* desired, uint8_t* current, uint64_t* epoch,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_OBJECT_H
