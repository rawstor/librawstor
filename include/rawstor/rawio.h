/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWIO_H
#define RAWIO_H

#include <rawstor/rawstor.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawIOQueue RawIOQueue;

typedef void RawIOEvent;

int rawio_queue_create(unsigned int depth, RawIOQueue** queue) RAWSTOR_NOEXCEPT;

void rawio_queue_delete(RawIOQueue* queue) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously opens a file (single-shot).
 *
 * This function initiates an asynchronous open operation on the specified file
 * path. The operation is performed in the background, and the provided callback
 * is invoked exactly once when the open completes (either successfully or with
 * an error). After the callback returns, the operation is complete and no
 * further callbacks will be triggered for this request.
 *
 * @param path   Path to the file to open. Must be a valid null‑terminated
 *               string. The caller must ensure that the memory remains valid
 *               until the callback is invoked.
 *
 * @param flags  File status flags and access modes, as defined in open(2).
 *               Standard flags include O_RDONLY, O_WRONLY, O_RDWR, O_CREAT,
 *               O_TRUNC, etc. The exact semantics follow the system's open(2).
 *
 * @param mode   File mode (permissions) used when O_CREAT is specified in
 *               flags. The value is modified by the process's umask in the
 *               usual way. If O_CREAT is not set, mode is ignored.
 *
 * @param cb     Callback function invoked when the open operation completes.
 *               The callback receives a ssize_t result:
 *               - If positive, it is the new file descriptor (>= 0) that can
 *                 be used for subsequent I/O operations.
 *               - If negative, it is the negative error code (e.g., -ENOENT,
 *                 -EACCES, -ENFILE). In case of an error, no file descriptor
 *                 is returned and the operation is considered failed.
 *
 * @param data   User-defined context pointer passed unchanged to the callback.
 *               Can be used to maintain application state.
 *
 * @return       0 on successful initiation of the asynchronous open operation.
 *               Negative error code on immediate failure (e.g., -EINVAL for
 *               invalid parameters). Note that the actual open result is
 *               delivered via the callback.
 *
 * @warning      The callback may be invoked from an I/O completion context.
 *               Avoid blocking operations inside the callback; instead, queue
 *               the file descriptor for later use.
 *
 * @warning      The returned file descriptor (if successful) is subject to the
 *               usual restrictions (e.g., non‑blocking mode may be set
 *               automatically by the underlying implementation). Check
 *               the actual flags if needed.
 *
 * @see          open(2) for standard synchronous open semantics.
 * @see          rawio_close() for closing the opened file descriptor.
 */
int rawio_open(
    RawIOQueue* queue, const char* path, int flags, mode_t mode,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously closes a file descriptor (single-shot).
 *
 * This function initiates an asynchronous close operation on the given file
 * descriptor. The operation is performed in the background, and the provided
 * callback is invoked exactly once when the close completes (either
 * successfully or with an error). After the callback returns, the operation is
 * complete and no further callbacks will be triggered for this request.
 *
 * @param fd    File descriptor to close. Must be a valid, open file descriptor
 *              that was previously obtained (e.g., from rawio_open() or
 *              rawio_accept()). After successful close, the descriptor becomes
 *              invalid and should not be used further.
 *
 * @param cb    Callback function invoked when the close operation completes.
 *              The callback receives a ssize_t result:
 *              - If zero (0), the descriptor was closed successfully.
 *              - If negative, it is the negative error code (e.g., -EBADF,
 *                -EIO). In case of an error, the descriptor may still be
 *                in an inconsistent state; the application should avoid using
 *                it.
 *
 * @param data  User-defined context pointer passed unchanged to the callback.
 *              Can be used to maintain application state.
 *
 * @return      0 on successful initiation of the asynchronous close operation.
 *              Negative error code on immediate failure (e.g., -EBADF if the
 *              descriptor is invalid or already closed). Note that the actual
 *              close result is delivered via the callback.
 *
 * @warning      The callback may be invoked from an I/O completion context.
 *               Avoid blocking operations inside the callback.
 *
 * @warning      After initiating an asynchronous close, the file descriptor
 *               should be considered "in transition". Do not attempt to use
 *               the descriptor in other I/O operations until the callback
 *               confirms completion (success or failure). If the close fails,
 *               the descriptor may still be open, but its state is unreliable.
 *
 * @warning      Closing a descriptor that has pending asynchronous operations
 *               may lead to those operations being cancelled or yielding errors
 *               (e.g., -ECANCELED). The behaviour is implementation‑defined,
 *               but it is recommended to cancel all operations on the fd first
 *               via rawio_cancel_all() before closing.
 *
 * @see          close(2) for standard synchronous close semantics.
 * @see          rawio_open() for opening files.
 */
int rawio_close(
    RawIOQueue* queue, int fd, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously polls a file descriptor for events (single-shot).
 *
 * This function initiates a one‑time asynchronous poll operation on the
 * specified file descriptor. When one or more of the requested events occur,
 * or an error happens, the provided callback is invoked exactly once. After
 * the callback returns, the operation is complete and no further callbacks
 * will be triggered for this request.
 *
 * @param fd    File descriptor to monitor. Must be a valid, open file
 *              descriptor.
 *
 * @param mask  Bitmask of events to monitor, composed of poll event flags
 *              (e.g., POLLIN, POLLOUT). Multiple events can be combined
 *              using bitwise OR.
 *
 * @param cb    Callback function invoked when the poll completes. The
 *              callback receives a ssize_t result:
 *              - If positive, it is the bitmask of events that occurred
 *                (subset of the requested mask).
 *              - If negative, it is the negative error code (e.g., -EBADF,
 *                -EINVAL). In case of an error, the operation is considered
 *                failed and no further action is taken.
 *
 * @param data  User-defined context pointer passed unchanged to the callback.
 *              Can be used to maintain application state.
 *
 * @return      0 on successful initiation of the asynchronous poll operation.
 *              Negative error code on failure (e.g., -EBADF, -EINVAL).
 *
 * @note        This is a single‑shot operation: after the callback is invoked,
 *              the operation terminates automatically. No explicit cancellation
 *              is required or possible (no event handle is returned).
 *
 * @warning     The callback may be invoked from an I/O completion context.
 *              Avoid blocking operations inside the callback; instead, queue
 *              the result for processing in a separate thread or context.
 *
 * @warning     Polling a descriptor that doesn't support the requested events
 *              may result in immediate callback invocation with an appropriate
 *              error code.
 *
 * @see         rawio_poll_multishot() for a persistent (multishot) version.
 * @see         poll(2) for standard poll semantics and event definitions.
 */
int rawio_poll(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Establishes a persistent multishot poll operation for monitoring file
 *        descriptor events.
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
 *              error happens. The callback receives a ssize_t result:
 *              - If positive, it is the bitmask of events that occurred
 *                (subset of the requested mask).
 *              - If negative, it is the negative error code (e.g., -EBADF,
 *                -EINVAL). In case of an error, the operation is automatically
 *                terminated and no further callbacks will be invoked.
 *
 * @param data  User-defined context pointer passed unchanged to each callback
 *              invocation. Can be used to maintain application state across
 *              asynchronous event notifications.
 *
 * @param event Output parameter that receives an opaque event handle for
 *              controlling the multishot poll operation. This handle must be
 *              used to cancel the operation via rawio_cancel(). The
 *              handle tracks the operation's lifecycle and must be preserved
 *              until the operation terminates.
 *
 * @return      0 on successful registration of the multishot poll operation.
 *              Negative error code on failure.
 *
 * @note        The poll operation remains active indefinitely until:
 *              - Explicitly canceled via rawio_cancel()
 *              - An error occurs (e.g., descriptor closure, unsupported event)
 *
 * @warning     After an error occurs, the operation automatically terminates.
 *              Calling rawio_cancel() on an already-terminated event is
 *              unnecessary and has no observable effect.
 *
 * @warning     The callback may be invoked from a completion context. Avoid
 *              blocking operations in the callback; instead, queue events for
 *              processing in a separate context.
 *
 * @warning     Polling a descriptor that doesn't support the requested events
 *              may result in immediate callback invocation with appropriate
 *              error codes or undefined behavior.
 *
 * @see         rawio_cancel() for operation termination.
 * @see         poll(2) for standard poll semantics and event definitions.
 */
int rawio_poll_multishot(
    RawIOQueue* queue, int fd, unsigned int mask,
    int (*cb)(ssize_t result, void* data), void* data, RawIOEvent** event
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously initiates a connection on a socket (single-shot).
 *
 * This function starts an asynchronous connect operation on the specified
 * socket file descriptor. The connection is established in the background,
 * and the provided callback is invoked exactly once when the operation
 * completes (either successfully or with an error). After the callback
 * returns, the operation is complete and no further callbacks will be
 * triggered for this request.
 *
 * @param fd      Socket file descriptor. Must be a valid socket created with
 *                socket(2). The socket should be set to non‑blocking mode
 *                (O_NONBLOCK) to ensure proper asynchronous behaviour.
 *
 * @param addr    Pointer to a sockaddr structure containing the target address
 *                to connect to. The structure must remain valid until the
 *                callback is invoked (i.e., it is the caller's responsibility
 *                to keep the memory alive).
 *
 * @param addrlen Length of the sockaddr structure pointed to by addr.
 *
 * @param cb      Callback function invoked when the connect operation
 *                completes. The callback receives a ssize_t result:
 *                - If zero, the connection was established successfully.
 *                - If negative, it is the negative error code (e.g.,
 * -ECONNREFUSED, -ETIMEDOUT, -EINPROGRESS). In case of an error, the connection
 * attempt has failed and the socket is left in an unspecified state; the caller
 * should close the socket.
 *
 * @param data    User-defined context pointer passed unchanged to the callback.
 *                Can be used to maintain application state.
 *
 * @return        0 on successful initiation of the asynchronous connect
 *                operation. Negative error code on immediate failure (e.g.,
 *                -EBADF, -EINVAL). Note that the actual connection result is
 *                delivered via the callback.
 *
 * @warning       The callback may be invoked from an I/O completion context.
 *                Avoid blocking operations inside the callback; instead, queue
 *                the connection result for processing in a separate thread or
 *                context.
 *
 * @warning       The socket must be non‑blocking. If the socket is blocking,
 *                the asynchronous behaviour may not work as expected.
 *
 * @warning       After a failed connection attempt, the socket may be unusable.
 *                The application should close the socket and create a new one
 *                for further connection attempts.
 *
 * @see           connect(2) for standard synchronous connect semantics.
 * @see           rawio_accept() for accepting incoming connections.
 */
int rawio_connect(
    RawIOQueue* queue, int fd, const struct sockaddr* addr, socklen_t addrlen,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Asynchronously accepts an incoming connection on a listening socket.
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
 *                The callback receives a ssize_t result:
 *                - If positive, it is the new connected socket descriptor.
 *                - If negative, it is the negative error code (e.g., -EAGAIN,
 *                  -ECONNABORTED). In case of an error, the operation is
 *                  considered failed and no further action is taken.
 *
 * @param data    User-defined context pointer passed unchanged to the callback.
 *
 * @return        0 on successful initiation of the asynchronous accept
 *                operation. Negative error code on failure (e.g., -EBADF,
 *                -EINVAL).
 *
 * @note          The caller is responsible for closing the client socket when
 *                no longer needed.
 *
 * @warning       The callback may be invoked from an I/O completion context.
 *                Avoid blocking operations inside the callback; instead, queue
 *                the new socket for processing in a separate thread or context.
 *
 * @see           rawio_accept_multishot() for a persistent version.
 * @see           accept(2) for standard synchronous accept semantics.
 */
int rawio_accept(
    RawIOQueue* queue, int fd, struct sockaddr* addr, socklen_t* addrlen,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Establishes a persistent multishot accept operation on a listening
 *        socket.
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
 *                The callback receives a ssize_t result:
 *                - If positive, it is the new connected socket descriptor.
 *                - If negative, it is the negative error code (e.g., -EBADF,
 *                  -EINVAL). In case of an error, the multishot operation is
 *                  automatically terminated and no further callbacks will be
 *                  invoked.
 *
 * @param data    User-defined context pointer passed unchanged to each callback
 *                invocation.
 *
 * @param event   Output parameter that receives an opaque event handle for
 *                controlling the multishot accept operation. This handle must
 *                be used to cancel the operation via `rawio_cancel()`.
 *                The handle remains valid until the operation terminates.
 *
 * @return        0 on successful registration of the multishot accept
 *                operation. Negative error code on failure.
 *
 * @note          The caller must close the client socket when finished.
 *
 * @note          The operation continues indefinitely until:
 *                - Explicitly canceled with `rawio_cancel()`
 *                - An error occurs (e.g., the listening socket is closed)
 *
 * @warning       After an error occurs, the operation automatically terminates.
 *                Calling `rawio_cancel()` on an already‑terminated event has
 *                no observable effect and no further callbacks are invoked.
 *
 * @warning       The callback is invoked from an I/O completion context.
 *                To maintain high throughput, avoid blocking operations inside
 *                the callback. Instead, queue the accepted socket for later
 *                processing.
 *
 * @see           rawio_accept() for a single‑shot version.
 * @see           rawio_cancel() for terminating the operation.
 * @see           accept(2), getpeername(2).
 */
int rawio_accept_multishot(
    RawIOQueue* queue, int fd, int (*cb)(ssize_t result, void* data),
    void* data, RawIOEvent** event
) RAWSTOR_NOEXCEPT;

/**
 * @brief Shared completion callback shape for rawio_read()/_readv()/
 *        _pread()/_preadv()/_recv()/_recvmsg()/_write()/_writev()/
 *        _pwrite()/_pwritev()/_send()/_sendmsg() below.
 *
 * @param result Non-negative on success -- the operation-specific result
 *               (e.g. number of bytes read/written, which may be less than
 *               requested due to EOF or a partial transfer). Negative on
 *               error: the (negated) errno for the operation, folding what
 *               used to be a separate `error` parameter into this same
 *               value instead of a second one.
 *
 * @param data   User-defined context pointer passed from the initiating
 *               function. This pointer is passed unchanged and can be used
 *               to maintain application state across asynchronous
 *               operations.
 *
 * @return       Operation control flag. Zero on success, negative on error.
 *
 * @note         The callback may be invoked from an I/O completion context
 *               (e.g., completion handler). Avoid blocking operations in the
 *               callback; instead, queue data or events for processing in a
 *               separate thread or context.
 */
int rawio_read(
    RawIOQueue* queue, int fd, void* buf, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_readv(
    RawIOQueue* queue, int fd, struct iovec* iov, unsigned int niov,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_pread(
    RawIOQueue* queue, int fd, void* buf, size_t size, off_t offset,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_preadv(
    RawIOQueue* queue, int fd, struct iovec* iov, unsigned int niov,
    off_t offset, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_recv(
    RawIOQueue* queue, int fd, void* buf, size_t size, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Establishes a persistent multishot recv operation.
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
 *                   complete.
 *                   - @p iov/@p niov are scatter-gather vectors pointing to
 *                     the received data in the ring buffer; the total data
 *                     received across all vectors equals @p result.
 *                   - @p result is non-negative on success -- the total
 *                     number of bytes received in this operation (may be
 *                     less than the requested size for partial receives;
 *                     zero indicates EOF, i.e. the connection closed
 *                     gracefully) -- or negative on error: the (negated)
 *                     errno for the operation. @c -ENOBUFS indicates ring
 *                     buffer overflow -- the receive operation has been
 *                     automatically terminated due to the producer
 *                     overtaking the consumer. No further callbacks are
 *                     invoked after any negative @p result. Other negative
 *                     values indicate socket or I/O errors.
 *                   - @p data is the same pointer passed as @p data below.
 *                   - Return value specifies the size for the next buffer
 *                     allocation in bytes: a non-negative value requests
 *                     that size for the next receive operation; a negative
 *                     value terminates the multishot operation immediately
 *                     (the exact negative value may be propagated as an
 *                     error code).
 *                   This callback is invoked from a completion context. For
 *                   optimal performance: process data quickly or copy to a
 *                   separate buffer, avoid system calls or blocking
 *                   operations, and keep the ring buffer moving by
 *                   returning promptly.
 *
 * @param data       User-defined context pointer passed unchanged to each
 *                   callback invocation. Useful for maintaining application
 *                   state across asynchronous operations.
 *
 * @param event      Output parameter that receives an opaque event handle.
 *                   This handle must be used to cancel the operation via
 *                   rawio_cancel(). The handle must be preserved until the
 *                   operation terminates (either via explicit cancellation or
 *                   error).
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
 *                   - Explicitly canceled via rawio_cancel()
 *                   - An error occurs (e.g., socket closure, buffer overflow)
 *
 * @warning          After an error occurs, the operation automatically cancels
 *                   itself. Calling rawio_cancel() on an already-terminated
 *                   event is unnecessary and has no observable effect.
 *
 * @see              rawio_cancel() for operation termination.
 */
int rawio_recv_multishot(
    RawIOQueue* queue, int fd, size_t entry_size, unsigned int entries,
    size_t size, unsigned int flags,
    ssize_t (*cb)(
        const struct iovec* iov, unsigned int niov, ssize_t result, void* data
    ),
    void* data, RawIOEvent** event
) RAWSTOR_NOEXCEPT;

int rawio_recvmsg(
    RawIOQueue* queue, int fd, struct msghdr* msg, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_write(
    RawIOQueue* queue, int fd, const void* buf, size_t size,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_writev(
    RawIOQueue* queue, int fd, const struct iovec* iov, unsigned int niov,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_pwrite(
    RawIOQueue* queue, int fd, const void* buf, size_t size, off_t offset,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_pwritev(
    RawIOQueue* queue, int fd, const struct iovec* iov, unsigned int niov,
    off_t offset, int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Request that previously submitted writes to @p fd reach stable
 *        storage.
 *
 * @param queue     Queue previously created by rawio_queue_create().
 * @param fd        File descriptor to sync.
 * @param datasync  If true, only data (not file metadata) needs to reach
 *                  stable storage (like `fdatasync()`); if false, both
 *                  data and metadata are synced (like `fsync()`).
 * @param cb        Callback invoked on completion.
 *                  - @p result is zero on success, or a negative errno on
 *                    failure. There's nothing else to report -- this
 *                    function has always used this combined result on its
 *                    own, unlike the read/write family's shared callback
 *                    shape.
 *                  - @p data is the same pointer passed as @p data below.
 *                  - Return zero on success. A negative errno value signals
 *                    an error back into the I/O completion machinery.
 * @param data      User-defined context pointer passed unchanged to @p cb.
 *
 * @return 0 if the sync was successfully queued; negative errno on
 *         immediate failure (in which case @p cb is never invoked). The
 *         actual sync result (success or failure) is delivered via @p cb.
 */
int rawio_fsync(
    RawIOQueue* queue, int fd, bool datasync,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_send(
    RawIOQueue* queue, int fd, const void* buf, size_t size, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

int rawio_sendmsg(
    RawIOQueue* queue, int fd, const struct msghdr* msg, unsigned int flags,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

/**
 * @brief Standalone async timer, not tied to any file descriptor.
 *
 * Unlike rawio_wait_timeout() (which bounds a single wait()/pump call),
 * this arms an ordinary cancelable operation that can be raced against
 * other pending ops (e.g. rawio_read()) -- cancel whichever one loses via
 * rawio_cancel() once the other's callback fires.
 *
 * @param queue  Queue previously created by rawio_queue_create().
 * @param usec   How long to wait, in microseconds, before @p cb fires.
 * @param cb     Callback invoked once the timer fires or is canceled.
 *               - @p result is zero once @p usec microseconds have
 *                 elapsed, or a negative errno (-ECANCELED) if
 *                 rawio_cancel() canceled it first. There's nothing else
 *                 to report -- like rawio_fsync(), this has always used
 *                 this combined result on its own.
 *               - @p data is the same pointer passed as @p data below.
 *               - Return zero on success. A negative errno value signals
 *                 an error back into the I/O completion machinery.
 * @param data   User-defined context pointer passed unchanged to @p cb.
 * @param event  Optional (may be NULL) output parameter that receives an
 *               opaque event handle for canceling the timer early via
 *               rawio_cancel(). The handle must not be used after @p cb
 *               has been invoked.
 *
 * @return 0 if the timer was successfully armed; negative errno on
 *         immediate failure (in which case @p cb is never invoked).
 *
 * @see rawio_wait_timeout() for bounding an entire wait()/pump call
 *      instead of a single operation.
 * @see rawio_cancel() for canceling the timer early.
 */
int rawio_timeout(
    RawIOQueue* queue, unsigned int usec, int (*cb)(ssize_t result, void* data),
    void* data, RawIOEvent** event
) RAWSTOR_NOEXCEPT;

int rawio_wait(RawIOQueue* queue) RAWSTOR_NOEXCEPT;

int rawio_wait_timeout(RawIOQueue* queue, unsigned int msec) RAWSTOR_NOEXCEPT;

/**
 * @brief Cancels an ongoing I/O operation and releases associated resources if
 *        any.
 *
 * This function gracefully terminates an I/O operation. It ensures that:
 *
 * 1. No further callbacks will be invoked after cancellation completes
 *
 * 2. All ring buffer entries are safely released if any
 *
 * 3. Any pending I/O operations are properly cleaned up
 *
 * @param event Event handle obtained from cancelable rawio I/O function.
 *              After successful cancellation, the handle becomes invalid and
 *              should not be used further. The caller does not need to free
 *              the handle - all associated resources are managed internally.
 *
 * @return      0 once the cancellation request has been submitted.
 *              Negative error code only on a genuine failure to submit that
 *              request; whether the target was actually found and canceled
 *              is not reported here.
 *
 * @note        This function is fire-and-forget: it returns as soon as the
 *              cancellation request has been submitted, without waiting for
 *              or reporting its outcome. If the target operation is still
 *              active, its completion callback will still be invoked once
 *              with the ECANCELED error code; after that callback returns,
 *              the operation is fully terminated and all resources are
 *              released. If the operation had already completed or
 *              terminated (including "already canceled") by the time this
 *              request reaches it, no additional callback is invoked and no
 *              error is reported -- that outcome is indistinguishable from
 *              an ordinary successful cancellation from the caller's side.
 *              The event handle must not be used again after calling
 *              rawio_cancel() on it, even though its cancellation callback
 *              may still be pending.
 *
 * @warning     After an error occurs in the multishot operation (e.g., socket
 *              error, ring buffer overflow with ENOBUFS), the operation
 *              automatically terminates. Calling `rawio_cancel()` in such
 *              cases is unnecessary and has no observable effect.
 *
 * @see         rawio_poll_multishot(), rawio_recv_multishot() for
 *              establishing multishot operations.
 *
 */
int rawio_cancel(RawIOQueue* queue, RawIOEvent* event) RAWSTOR_NOEXCEPT;

/**
 * @brief Cancel all ongoing I/O operations associated with a file descriptor.
 *
 * This function terminates all active I/O operations that were started on the
 * given file descriptor. After cancellation:
 *
 * - Each cancelled operation will invoke its completion callback once with the
 *   ECANCELED error code.
 *
 * - After those callbacks return, no further callbacks will occur for those
 *   operations.
 *
 * - All ring buffer entries and associated resources are safely released.
 *
 * - The file descriptor itself is not closed; only the operations are
 *   cancelled.
 *
 * @param fd    File descriptor whose pending I/O operations should be
 *              cancelled.
 *
 * @return      0 once the cancellation request has been submitted. Negative
 *              error code only on a genuine failure to submit that request.
 *
 * @note        This function is fire-and-forget: it returns as soon as the
 *              cancellation request has been submitted, without waiting for
 *              it to take effect. Completion callbacks for the cancelled
 *              operations will still be invoked once with the ECANCELED
 *              error code (e.g., via rawstor_wait()) before the operations
 *              are fully terminated. After those callbacks return, no
 *              further callbacks will occur.
 *
 * @see         rawio_cancel(RawIOEvent*)
 */
int rawio_cancel_all(RawIOQueue* queue, int fd) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWIO_H
