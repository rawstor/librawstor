#include "uring_queue.hpp"

#include "uring_event.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/socket.h>

#include <time.h>


namespace {


std::string engine_name = "uring";


} // unnamed


namespace rawstor {
namespace io {
namespace uring {


Queue::Queue(unsigned int depth):
    rawstor::io::Queue(depth),
    _events(0)
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


void Queue::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> e = Event::read(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::read(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> e = Event::read(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<Event> e = Event::read(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<Event> e = Event::read(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> e = Event::write(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::write(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> e = Event::write(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<Event> e = Event::write(*this, std::move(t));
    ++_events;
    e.release();
}


void Queue::write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<Event> e = Event::write(*this, std::move(t));
    ++_events;
    e.release();
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

    std::unique_ptr<Event> event(
        static_cast<Event*>(io_uring_cqe_get_data(cqe)));

    event->set_cqe(cqe);

    --_events;

    event->dispatch();
}


}}} // rawstor::io::uring
