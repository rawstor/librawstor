#ifndef RAWSTORIO_URING_EVENT_HPP
#define RAWSTORIO_URING_EVENT_HPP

#include <rawstorio/event.hpp>

#include <rawstor/io_event.h>

#include <liburing.h>

#include <cstddef>


namespace rawstor {
namespace io {
namespace uring {


class Queue;


class Event: public RawstorIOEvent {
    protected:
        io_uring_sqe *_sqe;
        io_uring_cqe *_cqe;

    public:
        Event(
            Queue &q,
            int fd, size_t size,
            RawstorIOCallback *cb, void *data);
        ~Event();

        inline void set_cqe(io_uring_cqe *cqe) noexcept {
            _cqe = cqe;
        }

        size_t result() const noexcept;
        int error() const noexcept;
};


class EventRead: public Event {
    public:
        EventRead(
            Queue &q,
            int fd, void *buf, size_t size,
            RawstorIOCallback *cb, void *data);
};


class EventReadV: public Event {
    public:
        EventReadV(
            Queue &q,
            int fd, iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);
};


class EventPRead: public Event {
    public:
        EventPRead(
            Queue &q,
            int fd, void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);
};


class EventPReadV: public Event {
    public:
        EventPReadV(
            Queue &q,
            int fd, iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);
};


class EventWrite: public Event {
    public:
        EventWrite(
            Queue &q,
            int fd, void *buf, size_t size,
            RawstorIOCallback *cb, void *data);
};


class EventWriteV: public Event {
    public:
        EventWriteV(
            Queue &q,
            int fd, iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);
};


class EventPWrite: public Event {
    public:
        EventPWrite(
            Queue &q,
            int fd, void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);
};


class EventPWriteV: public Event {
    public:
        EventPWriteV(
            Queue &q,
            int fd, iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);
};


}}} // rawstor::io::uring

#endif // RAWSTORIO_URING_EVENT_HPP

