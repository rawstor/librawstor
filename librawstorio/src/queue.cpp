#include "rawstorio/queue.hpp"
#include "rawstorio/queue.h"

#include <rawstorstd/gpp.hpp>

#include <cerrno>


namespace rawstor {
namespace io {


Queue::Queue(unsigned int depth):
    _impl(nullptr)
{
    _impl = rawstor_io_queue_create(depth);
    if (_impl == nullptr) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


Queue::~Queue() {
    rawstor_io_queue_delete(_impl);
}


void Queue::read(
    int fd,
    void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_read(
        _impl, fd,
        buf, size,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::readv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_readv(
        _impl, fd,
        iov, niov, size,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_pread(
        _impl, fd,
        buf, size, offset,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::preadv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_preadv(
        _impl, fd,
        iov, niov, size, offset,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::write(
    int fd,
    void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_write(
        _impl, fd,
        buf, size,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::writev(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_writev(
        _impl, fd,
        iov, niov, size,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::pwrite(
    int fd,
    void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_pwrite(
        _impl, fd,
        buf, size, offset,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Queue::pwritev(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    if (rawstor_io_queue_pwritev(
        _impl, fd,
        iov, niov, size, offset,
        cb, data))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


RawstorIOEvent* Queue::wait_event_timeout(unsigned int timeout) {
    RawstorIOEvent *event = rawstor_io_queue_wait_event_timeout(
        _impl, timeout);

    if (event == nullptr && errno != 0) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    return event;
}


void Queue::release_event(RawstorIOEvent *event) {
    rawstor_io_queue_release_event(_impl, event);
}


} // io
} // rawstor
