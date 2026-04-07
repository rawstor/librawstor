/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_RAWSTOR_H
#define RAWSTOR_RAWSTOR_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
#define RAWSTOR_NOEXCEPT noexcept
#else
#define RAWSTOR_NOEXCEPT
#endif

/**
 * Generic callback for asynchronous I/O operations.
 *
 * This callback is used for various asynchronous operations including read,
 * write, and poll. The meaning of the `result` parameter varies depending on
 * the operation type, while the error and data parameters remain consistent
 * across all operations.
 *
 * @param result Operation-specific result value:
 *               - For read operations: Number of bytes successfully read.
 *                 May be less than requested due to EOF or partial reads.
 *               - For write operations: Number of bytes successfully written.
 *                 May be less than requested due to partial writes.
 *               - For poll operations: Bitmask of events that occurred.
 *                 This is a subset of the events requested in the poll call.
 *
 * @param error  Error code from the operation.
 *               Zero indicates successful completion.
 *               Non-zero values indicate errors specific to the operation.
 *
 * @param data   User-defined context pointer passed from the initiating
 *               function. This pointer is passed unchanged and can be used to
 *               maintain application state across asynchronous operations.
 *
 * @return       Operation control flag. Zero on success, negative on error.
 *
 * @note         The callback may be invoked from an I/O completion context
 *               (e.g., completion handler). Avoid blocking operations in the
 *               callback; instead, queue data or events for processing in a
 *               separate thread or context.
 */
typedef int(RawstorIOCallback)(size_t result, int error, void* data);

/**
 * Callback for multishot receive operations with scatter-gather semantics.
 *
 * @param iov    Array of I/O vectors pointing to received data in the ring
 *               buffer. Each iovec represents a contiguous chunk of received
 *               data. The total data received across all vectors equals
 *               'result'.
 *
 * @param niov   Number of valid iovec entries in the array. Indicates how many
 *               buffer fragments contain received data.
 *
 * @param result Total number of bytes received in this operation. This is the
 *               sum of data across all iovec entries. May be less than the
 *               requested size for partial receives. Zero indicates EOF
 *               (connection closed gracefully).
 *
 * @param error  Error code from the receive operation.
 *               Zero indicates success.
 *               ENOBUFS indicates ring buffer overflow - the receive operation
 *               has been automatically terminated due to producer overtaking
 *               consumer.
 *               No further callbacks will be invoked. Other errors indicate
 *               socket or I/O errors.
 *
 * @param data   User context pointer from rawstor_fd_recv_multishot().
 *
 * @return       Specifies the size for the next buffer allocation in bytes.
 *               Positive value: Requested size for next receive operation.
 *               Negative value: Terminate the multishot operation immediately.
 *               The exact negative value may be propagated as an error code.
 *
 * @note         This callback is invoked from an completion context.
 *               For optimal performance:
 *               1. Process data quickly or copy to a separate buffer
 *               2. Avoid system calls or blocking operations
 *               3. Keep the ring buffer moving by returning promptly
 *
 * @warning      After returning a negative value or when error != 0, no further
 *               callbacks will be invoked, and the multishot operation
 *               terminates. The event handle becomes invalid and should not be
 *               canceled.
 */
typedef ssize_t(RawstorIOMultishotVectorCallback)(
    const struct iovec* iov, unsigned int niov, size_t result, int error,
    void* data
);

typedef void RawstorIOEvent;

/**
 * fd
 */

int rawstor_fd_poll(
    int fd, unsigned int mask, RawstorIOCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

/**
 * Establishes a persistent multishot poll operation for monitoring file
 * descriptor events.
 *
 * This function sets up a continuous poll operation that monitors the
 * specified file descriptor for events defined in the mask. When any of the
 * requested events occur (or an error happens), the provided callback is
 * invoked. The operation persists until explicitly canceled or until an error
 * occurs.
 *
 * @param fd    File descriptor to monitor. Must be a valid, open file
 *              descriptor.
 *
 * @param mask  Bitmask of events to monitor, composed of poll event flags.
 *              Multiple events can be combined using bitwise OR (e.g.,
 *              POLLIN | POLLOUT). Some events may not be supported on all
 *              descriptor types.
 *
 * @param cb    Callback function invoked when monitored events occur or an
 *              error happens. The callback receives the event mask of occurred
 *              events and any error code.
 *
 * @param data  User-defined context pointer passed unchanged to each callback
 *              invocation. Can be used to maintain application state across
 *              asynchronous event notifications.
 *
 * @param event Output parameter that receives an opaque event handle for
 *              controlling the multishot poll operation. This handle must be
 *              used to cancel the operation via rawstor_fd_cancel(). The
 *              handle tracks the operation's lifecycle and must be preserved
 *              until the operation terminates.
 *
 * @return      0 on successful registration of the multishot poll operation.
 *              Negative error code on failure.
 *
 * @note        The poll operation remains active indefinitely until:
 *              - Explicitly canceled via rawstor_fd_cancel()
 *              - An error occurs (e.g., descriptor closure, unsupported event)
 *
 * @warning     After an error occurs, the operation automatically terminates.
 *              Calling rawstor_fd_cancel() on an already-terminated event is
 *              unnecessary and will return -ENOENT.
 *
 * @warning     The callback may be invoked from an completion context. Avoid
 *              blocking operations in the callback; instead, queue events for
 *              processing in a separate context.
 *
 * @warning     Polling a descriptor that doesn't support the requested events
 *              may result in immediate callback invocation with appropriate
 *              error codes or undefined behavior.
 *
 * @see         rawstor_fd_cancel() for operation termination.
 * @see         poll(2) for standard poll semantics and event definitions.
 */
int rawstor_fd_poll_multishot(
    int fd, unsigned int mask, RawstorIOCallback* cb, void* data,
    RawstorIOEvent** event
) RAWSTOR_NOEXCEPT;

/**
 * Asynchronously accepts an incoming connection on a listening socket.
 *
 * This function initiates an asynchronous accept operation on the specified
 * listening socket. When a new connection arrives, the provided callback is
 * invoked with the new client socket descriptor. The address of the connecting
 * client is stored in the provided sockaddr structure.
 *
 * @param fd      Listening socket file descriptor. Must be bound to a local
 *                address and listening for connections (via listen()).
 *
 * @param addr    Pointer to a sockaddr structure that will receive the address
 *                of the connecting client. This memory must remain valid until
 *                the callback is invoked. May be NULL if the client address
 *                is not required.
 *
 * @param addrlen Pointer to a socklen_t that on input specifies the size of
 *                the buffer pointed to by addr. This memory must remain valid
 *                until the callback is invoked. On output, it contains the
 *                actual size of the client address (may be less than or equal
 *                to the input value). Cannot be NULL if addr is non-NULL.
 *
 * @param cb      Callback function invoked when the accept operation completes.
 *                On success, the `result` parameter contains the new connected
 *                socket descriptor (cast to size_t). On error, `result` is 0
 *                and `error` contains the error code (e.g., EAGAIN,
 *                ECONNABORTED).
 *
 * @param data    User-defined context pointer passed unchanged to the callback.
 *
 * @return        0 on successful initiation of the asynchronous accept
 *                operation. Negative error code on failure (e.g., -EBADF,
 *                -EINVAL).
 *
 * @note          The caller
 *                is responsible for closing the client socket when no longer
 *                needed.
 *
 * @warning       The callback may be invoked from an I/O completion context.
 *                Avoid blocking operations inside the callback; instead, queue
 *                the new socket for processing in a separate thread or context.
 *
 * @see           rawstor_fd_accept_multishot() for a persistent version.
 * @see           accept(2) for standard synchronous accept semantics.
 */
int rawstor_fd_accept(
    int fd, struct sockaddr* addr, socklen_t* addrlen, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

/**
 * Establishes a persistent multishot accept operation on a listening socket.
 *
 * This function sets up a continuous asynchronous accept operation that
 * invokes the provided callback for each incoming connection. The operation
 * remains active until explicitly canceled or until an error occurs. Unlike
 * the single‑shot version, this variant does not provide client address
 * parameters; the application must obtain the client address using
 * `getpeername()` on the newly accepted socket if needed.
 *
 * @param fd      Listening socket file descriptor. Must be bound and listening.
 *
 * @param cb      Callback function invoked for each incoming connection.
 *                On success, the `result` parameter contains the new connected
 *                socket descriptor (cast to size_t). The `error` parameter is
 *                0. On error (e.g., socket closure, invalid state), `result` is
 *                0 and `error` contains the error code.
 *
 * @param data    User-defined context pointer passed unchanged to each callback
 *                invocation.
 *
 * @param event   Output parameter that receives an opaque event handle for
 *                controlling the multishot accept operation. This handle must
 *                be used to cancel the operation via `rawstor_fd_cancel()`.
 *                The handle remains valid until the operation terminates.
 *
 * @return        0 on successful registration of the multishot accept
 *                operation. Negative error code on failure.
 *
 * @note          The client socket descriptor passed to the callback is already
 *                in non‑blocking mode (if supported by the implementation).
 *                The caller must close the client socket when finished.
 *
 * @note          The operation continues indefinitely until:
 *                - Explicitly canceled with `rawstor_fd_cancel()`
 *                - An error occurs (e.g., the listening socket is closed)
 *
 * @warning       After an error occurs, the operation automatically terminates.
 *                Calling `rawstor_fd_cancel()` on an already‑terminated event
 *                returns `-ENOENT` and no further callbacks are invoked.
 *
 * @warning       The callback is invoked from an I/O completion context.
 *                To maintain high throughput, avoid blocking operations inside
 *                the callback. Instead, queue the accepted socket for later
 *                processing.
 *
 * @see           rawstor_fd_accept() for a single‑shot version.
 * @see           rawstor_fd_cancel() for terminating the operation.
 * @see           accept(2), getpeername(2).
 */
int rawstor_fd_accept_multishot(
    int fd, RawstorIOCallback* cb, void* data, RawstorIOEvent** event
) RAWSTOR_NOEXCEPT;

int rawstor_fd_read(
    int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_readv(
    int fd, struct iovec* iov, unsigned int niov, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_pread(
    int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_preadv(
    int fd, struct iovec* iov, unsigned int niov, off_t offset,
    RawstorIOCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_recv(
    int fd, void* buf, size_t size, unsigned int flags, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

/**
 * Establishes a persistent multishot recv operation.
 *
 * Continuously receives data into a circular buffer, invoking the callback for
 * each completed I/O operation. The operation persists until canceled or until
 * an error occurs. Designed for high-throughput socket I/O with zero-copy
 * semantics.
 *
 * @param fd         File descriptor of the socket to receive from. Must be a
 *                   valid, connected TCP socket supporting non-blocking I/O.
 *
 * @param entry_size Size of each buffer entry in the ring buffer. Must be a
 *                   power of two.
 *
 * @param entries    Total number of buffer entries in the ring buffer. Must be
 *                   a power of two. Total buffer capacity is
 *                   entry_size × entries. Choose based on expected throughput
 *                   and desired memory footprint.
 *
 * @param size       Initial receive size in bytes for the first operation.
 *                   This parameter primarily affects the first buffer
 *                   allocation.
 *
 * @param flags      Receive flags passed to the underlying recv operation.
 *                   Standard socket flags. Refer to recv(2) for details.
 *
 * @param cb         Callback function invoked when receive operations
 *                   complete. The callback receives scatter-gather vectors
 *                   pointing to the received data. The return value specifies
 *                   the size for the next buffer (see callback documentation).
 *
 * @param data       User-defined context pointer passed unchanged to each
 *                   callback invocation. Useful for maintaining application
 *                   state across asynchronous operations.
 *
 * @param event      Output parameter that receives an opaque event handle.
 *                   This handle must be used to cancel the operation via
 *                   rawstor_fd_cancel(). The handle must be preserved until
 *                   the operation terminates (either via explicit
 *                   cancellation or error).
 *
 * @return           0 on successful registration of the multishot operation.
 *                   Negative error code on failure.
 *
 * @note             The ring buffer operates in a circular principle. When the
 *                   producer (network receive) overtakes the consumer (callback
 *                   processing), an overflow occurs, triggering an ENOBUFS
 *                   error in the callback and automatic termination.
 *
 * @warning          Once initiated, the operation continues indefinitely until:
 *                   - Explicitly canceled via rawstor_fd_cancel()
 *                   - An error occurs (e.g., socket closure, buffer overflow)
 *
 * @warning          After an error occurs, the operation automatically cancels
 *                   itself. Calling rawstor_fd_cancel() on an
 *                   already-terminated event is unnecessary and will return
 *                   -ENOENT.
 *
 * @see              rawstor_fd_cancel() for operation termination.
 */
int rawstor_fd_recv_multishot(
    int fd, size_t entry_size, unsigned int entries, size_t size,
    unsigned int flags, RawstorIOMultishotVectorCallback* cb, void* data,
    RawstorIOEvent** event
) RAWSTOR_NOEXCEPT;

int rawstor_fd_recvmsg(
    int fd, struct msghdr* msg, unsigned int flags, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_write(
    int fd, const void* buf, size_t size, RawstorIOCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_writev(
    int fd, const struct iovec* iov, unsigned int niov, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_pwrite(
    int fd, const void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_pwritev(
    int fd, const struct iovec* iov, unsigned int niov, off_t offset,
    RawstorIOCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_send(
    int fd, const void* buf, size_t size, unsigned int flags,
    RawstorIOCallback* cb, void* data
) RAWSTOR_NOEXCEPT;

int rawstor_fd_sendmsg(
    int fd, const struct msghdr* msg, unsigned int flags, RawstorIOCallback* cb,
    void* data
) RAWSTOR_NOEXCEPT;

/**
 * Cancels an ongoing IO operation and releases associated resources if any.
 *
 * This function gracefully terminates an IO operation. It ensures that:
 * 1. No further callbacks will be invoked after cancellation completes
 * 2. All ring buffer entries are safely released if any
 * 3. Any pending I/O operations are properly cleaned up
 *
 * @param event Event handle obtained from cancelable rawstor IO function.
 *              After successful cancellation, the handle becomes invalid and
 *              should not be used further. The caller does not need to free
 *              the handle - all associated resources are managed internally.
 *
 * @return      0 on successful cancellation.
 *              Negative error code on failure:
 *              -ENOENT Event handle does not correspond to an active operation
 *              (possibly already cleaned up)
 *
 * @note        Cancellation is synchronous from the caller's perspective: the
 *              function returns immediately after initiating the cancellation.
 * However, the completion callback will still be invoked once with the
 *              ECANCELED error code to indicate that the operation has been
 * canceled. After that callback returns, the operation is fully terminated, all
 * resources are released, and no further callbacks will occur. If the operation
 *              was already completed or terminated due to an error, calling
 * this function will return -ENOENT and no additional callback will be invoked.
 *              The event handle becomes invalid immediately upon successful
 * return from rawstor_fd_cancel() and must not be used afterwards, even though
 *              the cancellation callback may still be pending.
 *
 * @warning     After an error occurs in the multishot operation (e.g., socket
 *              error, ring buffer overflow with ENOBUFS), the operation
 *              automatically terminates. Calling `rawstor_fd_cancel()` in such
 *              cases is unnecessary and will return -ENOENT.
 *
 * @see         rawstor_fd_poll_multishot(), rawstor_fd_recv_multishot() for
 *              establishing multishot operations.
 *
 */
int rawstor_fd_cancel(RawstorIOEvent* event) RAWSTOR_NOEXCEPT;

/**
 * Lib
 */

struct RawstorOpts {
    unsigned int wait_timeout;
    unsigned int io_attempts;
    unsigned int sessions;
    unsigned int so_sndtimeo;
    unsigned int so_rcvtimeo;
    unsigned int tcp_user_timeout;
};

int rawstor_initialize(const struct RawstorOpts* opts) RAWSTOR_NOEXCEPT;

void rawstor_terminate(void) RAWSTOR_NOEXCEPT;

int rawstor_wait(void) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_RAWSTOR_H
