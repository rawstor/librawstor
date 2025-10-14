#include "uring_queue.hpp"

#include "uring_event.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/socket.h>

#include <time.h>


namespace {


std::string engine_name = "poll";


} // unnamed


namespace rawstor {
namespace io {
namespace uring {


Queue::Queue(unsigned int depth):
    rawstor::io::Queue(depth)
{
    int res = io_uring_queue_init(depth, &_ring, 0);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    };
}


Queue::~Queue() {
    io_uring_queue_exit(&_ring);
}


const std::string& Queue::engine_name() {
    return ::engine_name;
}


void Queue::setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 4096 * 64 * 4;

    res = rawstor_socket_set_snd_bufsize(fd, bufsize);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_rcv_bufsize(fd, bufsize);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_nodelay(fd);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


void Queue::read(
    int fd,
    void *buf, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventRead(
        *this, fd, buf, size, std::move(t));
    ++_events;
}


void Queue::readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventReadV(
        *this, fd, iov, niov, size, std::move(t));
    ++_events;
}


void Queue::pread(
    int fd, void *buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventPRead(
        *this, fd, buf, size, offset, std::move(t));
    ++_events;
}


void Queue::preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventPReadV(
        *this, fd, iov, niov, size, offset, std::move(t));
    ++_events;
}


void Queue::write(
    int fd, void *buf, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventWrite(
        *this, fd, buf, size, std::move(t));
    ++_events;
}


void Queue::writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventWriteV(
        *this, fd, iov, niov, size, std::move(t));
    ++_events;
}


void Queue::pwrite(
    int fd, void *buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventPWrite(
        *this, fd, buf, size, offset, std::move(t));
    ++_events;
}


void Queue::pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    new rawstor::io::uring::EventPWriteV(
        *this, fd, iov, niov, size, offset, std::move(t));
    ++_events;
}


bool Queue::empty() const noexcept {
    return _events == 0;
}


void Queue::wait(unsigned int timeout) {
    int res;
    io_uring_cqe *cqe;
    __kernel_timespec ts = {
        .tv_sec = 0,
        .tv_nsec = 1000000u * timeout
    };

    if (io_uring_sq_ready(&_ring) > 0) {
        /**
         * TODO: Replace with io_uring_submit_wait_cqe_timeout and do something
         * with sigmask.
         */
        res = io_uring_submit(&_ring);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
        res = io_uring_wait_cqe_timeout(&_ring, &cqe, &ts);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    } else {
        res = io_uring_wait_cqe_timeout(&_ring, &cqe, &ts);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    rawstor::io::uring::Event *event = static_cast<rawstor::io::uring::Event*>(
        io_uring_cqe_get_data(cqe));

    event->set_cqe(cqe);

    --_events;

    try {
        event->dispatch();
    } catch (...) {
        delete event;
        throw;
    }

    delete event;
}


}}} // rawstor::io::uring
