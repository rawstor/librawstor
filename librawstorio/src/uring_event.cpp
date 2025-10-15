#include "uring_event.hpp"

#include "uring_queue.hpp"

#include <rawstorstd/gpp.hpp>

#include <rawstor/io_event.h>

#include <memory>

#include <cerrno>
#include <cstddef>


namespace rawstor {
namespace io {
namespace uring {


Event::Event(
    Queue &q, int fd, std::unique_ptr<rawstor::io::Task> t):
    RawstorIOEvent(q, fd, std::move(t)),
    _sqe(io_uring_get_sqe(q.ring())),
    _cqe(nullptr)
{
    if (_sqe == nullptr) {
        RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_sqe_set_data(_sqe, this);
}


Event::~Event() {
    if (_cqe != nullptr) {
        io_uring_cqe_seen(static_cast<Queue&>(queue()).ring(), _cqe);
    }
}


std::unique_ptr<Event> Event::read(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_read(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskScalar*>(
            event->_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(
            event->_t.get())->size(),
        0);
    return event;
}


std::unique_ptr<Event> Event::read(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskVector> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_readv(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskVector*>(
            event->_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(
            event->_t.get())->niov(),
        0);
    return event;
}


std::unique_ptr<Event> Event::read(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskScalarPositional> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_read(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskScalarPositional*>(
            event->_t.get())->buf(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            event->_t.get())->size(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            event->_t.get())->offset());
    return event;
}


std::unique_ptr<Event> Event::read(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskVectorPositional> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_readv(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskVectorPositional*>(
            event->_t.get())->iov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            event->_t.get())->niov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            event->_t.get())->offset());
    return event;
}


std::unique_ptr<Event> Event::write(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_write(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskScalar*>(
            event->_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(
            event->_t.get())->size(),
        0);
    return event;
}


std::unique_ptr<Event> Event::write(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskVector> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_writev(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskVector*>(
            event->_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(
            event->_t.get())->niov(),
        0);
    return event;
}


std::unique_ptr<Event> Event::write(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskScalarPositional> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_write(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskScalarPositional*>(
            event->_t.get())->buf(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            event->_t.get())->size(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            event->_t.get())->offset());
    return event;
}


std::unique_ptr<Event> Event::write(
    Queue &q,
    int fd, std::unique_ptr<rawstor::io::TaskVectorPositional> t)
{
    std::unique_ptr<Event> event = std::make_unique<Event>(q, fd, std::move(t));
    io_uring_prep_writev(
        event->_sqe,
        fd,
        static_cast<rawstor::io::TaskVectorPositional*>(
            event->_t.get())->iov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            event->_t.get())->niov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            event->_t.get())->offset());
    return event;
}


size_t Event::result() const noexcept {
    return (_cqe != nullptr && _cqe->res >= 0) ? _cqe->res : 0;
}


int Event::error() const noexcept {
    return (_cqe != nullptr && _cqe->res < 0) ? -_cqe->res : 0;
}


}}} // rawstor::io::uring
