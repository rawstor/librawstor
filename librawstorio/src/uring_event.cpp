#include "uring_event.hpp"

#include "uring_queue.hpp"

#include <rawstorstd/gpp.hpp>

#include <rawstor/io_event.h>

#include <cerrno>
#include <cstddef>


namespace rawstor {
namespace io {
namespace uring {


Event::Event(
    Queue &q,
    int fd, size_t size,
    std::unique_ptr<rawstor::io::Callback> cb):
    RawstorIOEvent(q, fd, size, std::move(cb)),
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


size_t Event::result() const noexcept {
    return (_cqe != nullptr && _cqe->res >= 0) ? _cqe->res : 0;
}


int Event::error() const noexcept {
    return (_cqe != nullptr && _cqe->res < 0) ? -_cqe->res : 0;
}


EventRead::EventRead(
    Queue &q,
    int fd, void *buf, size_t size,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_read(_sqe, fd, buf, size, 0);
}


EventReadV::EventReadV(
    Queue &q,
    int fd, iovec *iov, unsigned int niov, size_t size,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_readv(_sqe, fd, iov, niov, 0);
}


EventPRead::EventPRead(
    Queue &q,
    int fd, void *buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_read(_sqe, fd, buf, size, offset);
}


EventPReadV::EventPReadV(
    Queue &q,
    int fd, iovec *iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_readv(_sqe, fd, iov, niov, offset);
}


EventWrite::EventWrite(
    Queue &q,
    int fd, void *buf, size_t size,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_write(_sqe, fd, buf, size, 0);
}


EventWriteV::EventWriteV(
    Queue &q,
    int fd, iovec *iov, unsigned int niov, size_t size,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_writev(_sqe, fd, iov, niov, 0);
}


EventPWrite::EventPWrite(
    Queue &q,
    int fd, void *buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_write(_sqe, fd, buf, size, offset);
}


EventPWriteV::EventPWriteV(
    Queue &q,
    int fd, iovec *iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Callback> cb):
    Event(q, fd, size, std::move(cb))
{
    io_uring_prep_writev(_sqe, fd, iov, niov, offset);
}


}}} // rawstor::io::uring
