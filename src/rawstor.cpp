#include <rawstor.h>

#include "opts.h"
#include "rawstor_internals.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/uri.hpp>

#include <rawstorio/callback.hpp>
#include <rawstorio/event.hpp>
#include <rawstorio/queue.hpp>

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


namespace {


class Callback: public rawstor::io::Callback {
    private:
        RawstorIOCallback *_cb;
        void *_data;

    public:
        Callback(RawstorIOCallback *cb, void *data):
            _cb(cb),
            _data(data)
        {}

        void operator()(RawstorIOEvent *event) {
            int res = _cb(event, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }
};


} // unnamed


namespace rawstor {


rawstor::io::Queue *io_queue;


} // rawstor


int rawstor_initialize(const struct RawstorOpts *opts) {
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
    rawstor_opts_terminate();
err_opts_initialize:
    rawstor_logging_terminate();
err_logging_initialize:
    return res;
}


void rawstor_terminate() {
    delete rawstor::io_queue;
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->read(
            fd, buf, size,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->pread(
            fd, buf, size, offset,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->readv(
            fd, iov, niov, size,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->preadv(
            fd, iov, niov, size, offset,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->write(
            fd, buf, size,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->pwrite(
            fd, buf, size, offset,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->writev(
            fd, iov, niov, size,
            std::move(c));
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
        std::unique_ptr<Callback> c = std::make_unique<Callback>(cb, data);
        rawstor::io_queue->pwritev(
            fd, iov, niov, size, offset,
            std::move(c));
        return 0;
    } catch (std::system_error &e) {
        return -e.code().value();
    }
}
