#include <rawstor.h>

#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstorstd/logging.h>
#include <rawstorstd/socket_address.hpp>

#include <rawstorio/queue.hpp>
#include <rawstorio/event.hpp>

#include <sys/types.h>
#include <sys/uio.h>

#include <memory>
#include <stdexcept>
#include <system_error>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>


#define QUEUE_DEPTH 256
#define DEFAULT_OST_HOST "127.0.0.1"
#define DEFAULT_OST_PORT 8080


namespace {


rawstor::SocketAddress* _default_ost = nullptr;


void default_ost_initialize(
    const struct RawstorSocketAddress *default_ost)
{
    _default_ost = new rawstor::SocketAddress(
        (default_ost != nullptr && default_ost->host != nullptr) ?
            default_ost->host :
            DEFAULT_OST_HOST,
        (default_ost != nullptr && default_ost->port != 0) ?
            default_ost->port :
            DEFAULT_OST_PORT);
}


void default_ost_terminate() {
    if (_default_ost != nullptr) {
        delete _default_ost;
        _default_ost = nullptr;
    }
}


} // unnamed


namespace rawstor {


rawstor::io::Queue *io_queue;


const SocketAddress& default_ost() {
    return *_default_ost;
}


} // rawstor


int rawstor_initialize(
    const struct RawstorOpts *opts,
    const struct RawstorSocketAddress *default_ost)
{
    int res = 0;

    assert(rawstor::io_queue == nullptr);

    res = rawstor_logging_initialize();
    if (res) {
        goto err_logging_initialize;
    }

    rawstor_info(
        "Rawstor compiled with IO queue engine: %s\n",
        rawstor::io::Queue::engine_name().c_str());

    res = rawstor_opts_initialize(opts);
    if (res) {
        goto err_opts_initialize;
    }

    try {
        default_ost_initialize(default_ost);
    } catch (std::bad_alloc &) {
        res = -ENOMEM;
        goto err_default_ost_initialize;
    }

    try {
        std::unique_ptr<rawstor::io::Queue> q = rawstor::io::Queue::create(
            QUEUE_DEPTH);
        rawstor::io_queue = q.get();
        q.release();
    } catch (std::bad_alloc &) {
        res = -ENOMEM;
        goto err_io_queue;
    }

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
    delete rawstor::io_queue;
    default_ost_terminate();
    rawstor_opts_terminate();
    rawstor_logging_terminate();
}


RawstorIOEvent* rawstor_wait_event() {
    try {
        return rawstor::io_queue->wait_event(rawstor_opts_wait_timeout());
    } catch (std::system_error &e) {
        errno = e.code().value();
        return nullptr;
    }
}


int rawstor_dispatch_event(RawstorIOEvent *event) {
    try {
        event->dispatch();
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


void rawstor_release_event(RawstorIOEvent *event) {
    rawstor::io_queue->release_event(event);
}


int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->read(
            fd, buf, size,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->pread(
            fd, buf, size, offset,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->readv(
            fd, iov, niov, size,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->preadv(
            fd, iov, niov, size, offset,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->write(
            fd, buf, size,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->pwrite(
            fd, buf, size, offset,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->writev(
            fd, iov, niov, size,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}


int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    try {
        rawstor::io_queue->pwritev(
            fd, iov, niov, size, offset,
            cb, data);
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}
