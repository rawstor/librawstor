#include <rawstor.h>

#include "object_internals.h"
#include "opts.h"

#include <rawstorstd/logging.h>

#include <rawstorio/queue.h>
#include <rawstorio/event.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define QUEUE_DEPTH 256


static RawstorIOQueue *_rawstor_io_queue = NULL;


int rawstor_initialize(
    const struct RawstorOptsIO *opts_io,
    const struct RawstorOptsOST *opts_ost)
{
    assert(_rawstor_io_queue == NULL);

    if (rawstor_logging_initialize()) {
        goto err_logging_initialize;
    }

    rawstor_info(
        "Rawstor compiled with IO queue engine: %s\n",
        rawstor_io_queue_engine_name());

    rawstor_info(
        "Rawstor compiled with object backend: %s\n",
        rawstor_object_backend_name());

    if (rawstor_opts_initialize(opts_io, opts_ost)) {
        goto err_opts_initialize;
    }

    _rawstor_io_queue = rawstor_io_queue_create(QUEUE_DEPTH);
    if (_rawstor_io_queue == NULL) {
        goto err_io_queue;
    };

    return 0;

err_io_queue:
    rawstor_opts_terminate();
err_opts_initialize:
    rawstor_logging_terminate();
err_logging_initialize:
    return -errno;
}


void rawstor_terminate(void) {
    rawstor_io_queue_delete(_rawstor_io_queue);
    rawstor_opts_terminate();
    rawstor_logging_terminate();
}


RawstorIOEvent* rawstor_wait_event(void) {
    return rawstor_io_queue_wait_event_timeout(
        _rawstor_io_queue,
        rawstor_opts_io_wait_timeout(NULL));
}


int rawstor_dispatch_event(RawstorIOEvent *event) {
    return rawstor_io_event_dispatch(event);
}


void rawstor_release_event(RawstorIOEvent *event) {
    rawstor_io_queue_release_event(_rawstor_io_queue, event);
}


int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_read(
        _rawstor_io_queue,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_pread(
        _rawstor_io_queue,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_readv(
        _rawstor_io_queue,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_preadv(
        _rawstor_io_queue,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_write(
        _rawstor_io_queue,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_pwrite(
        _rawstor_io_queue,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_writev(
        _rawstor_io_queue,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_pwritev(
        _rawstor_io_queue,
        fd, iov, niov, size, offset,
        cb, data);
}
