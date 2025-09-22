#include <rawstor.h>

#include "object_internals.h"
#include "opts.h"
#include "rawstor_internals.h"

#include <rawstorstd/logging.h>

#include <rawstorio/queue.h>
#include <rawstorio/event.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>


#define QUEUE_DEPTH 256
#define DEFAULT_OST_HOST "127.0.0.1"
#define DEFAULT_OST_PORT 8080


RawstorIOQueue *rawstor_io_queue = nullptr;


namespace {


static struct RawstorSocketAddress _default_ost = {};


int default_ost_initialize(
    const struct RawstorSocketAddress *default_ost)
{
    int res = 0;

    _default_ost.host = (default_ost != nullptr && default_ost->host != nullptr) ?
        strdup(default_ost->host) :
        strdup(DEFAULT_OST_HOST);
    if (_default_ost.host == nullptr) {
        res = -errno;
        errno = 0;
        goto err_host;
    }

    _default_ost.port = (default_ost != nullptr && default_ost->port != 0) ?
        default_ost->port :
        DEFAULT_OST_PORT;

    return 0;

err_host:
    return res;
}


void default_ost_terminate() {
    free(_default_ost.host);
}


} // unnamed


int rawstor_initialize(
    const struct RawstorOpts *opts,
    const struct RawstorSocketAddress *default_ost)
{
    int res = 0;

    assert(rawstor_io_queue == nullptr);

    res = rawstor_logging_initialize();
    if (res) {
        goto err_logging_initialize;
    }

    rawstor_info(
        "Rawstor compiled with IO queue engine: %s\n",
        rawstor_io_queue_engine_name());

    rawstor_info(
        "Rawstor compiled with object backend: %s\n",
        rawstor_object_backend_name());

    res = rawstor_opts_initialize(opts);
    if (res) {
        goto err_opts_initialize;
    }

    res = default_ost_initialize(default_ost);
    if (res) {
        goto err_default_ost_initialize;
    }

    rawstor_io_queue = rawstor_io_queue_create(QUEUE_DEPTH);
    if (rawstor_io_queue == nullptr) {
        res = -errno;
        errno = 0;
        goto err_io_queue;
    };

    return 0;

err_io_queue:
    default_ost_terminate();
err_default_ost_initialize:
    rawstor_opts_terminate();
err_opts_initialize:
    rawstor_logging_terminate();
err_logging_initialize:
    return res;
}


void rawstor_terminate() {
    rawstor_io_queue_delete(rawstor_io_queue);
    default_ost_terminate();
    rawstor_opts_terminate();
    rawstor_logging_terminate();
}


const struct RawstorSocketAddress* rawstor_default_ost() {
    return &_default_ost;
}


RawstorIOEvent* rawstor_wait_event() {
    return rawstor_io_queue_wait_event_timeout(
        rawstor_io_queue,
        rawstor_opts_wait_timeout());
}


int rawstor_dispatch_event(RawstorIOEvent *event) {
    return rawstor_io_event_dispatch(event);
}


void rawstor_release_event(RawstorIOEvent *event) {
    rawstor_io_queue_release_event(rawstor_io_queue, event);
}


int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_read(
        rawstor_io_queue,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_pread(
        rawstor_io_queue,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_readv(
        rawstor_io_queue,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_preadv(
        rawstor_io_queue,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_write(
        rawstor_io_queue,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_pwrite(
        rawstor_io_queue,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_writev(
        rawstor_io_queue,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_queue_pwritev(
        rawstor_io_queue,
        fd, iov, niov, size, offset,
        cb, data);
}
