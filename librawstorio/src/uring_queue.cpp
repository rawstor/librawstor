#include "uring_queue.hpp"

#include "uring_event.hpp"

#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/socket.h>

#include <liburing.h>

#include <time.h>

namespace {

std::string engine_name = "uring";

} // namespace

namespace rawstor {
namespace io {
namespace uring {

Queue::Queue(unsigned int depth) : rawstor::io::Queue(depth) {
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

rawstor::io::Event* Queue::poll(std::unique_ptr<rawstor::io::TaskPoll> t) {
    std::unique_ptr<EventPoll> event =
        std::make_unique<EventPoll>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event* Queue::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<EventScalarRead> event =
        std::make_unique<EventScalarRead>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event* Queue::read(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<EventVectorRead> event =
        std::make_unique<EventVectorRead>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event*
Queue::read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<EventScalarPositionalRead> event =
        std::make_unique<EventScalarPositionalRead>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event*
Queue::read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<EventVectorPositionalRead> event =
        std::make_unique<EventVectorPositionalRead>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event* Queue::read(std::unique_ptr<rawstor::io::TaskMessage> t) {
    std::unique_ptr<EventMessageRead> event =
        std::make_unique<EventMessageRead>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event* Queue::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<EventScalarWrite> event =
        std::make_unique<EventScalarWrite>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event* Queue::write(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<EventVectorWrite> event =
        std::make_unique<EventVectorWrite>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event*
Queue::write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<EventScalarPositionalWrite> event =
        std::make_unique<EventScalarPositionalWrite>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event*
Queue::write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<EventVectorPositionalWrite> event =
        std::make_unique<EventVectorPositionalWrite>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

rawstor::io::Event* Queue::write(std::unique_ptr<rawstor::io::TaskMessage> t) {
    std::unique_ptr<EventMessageWrite> event =
        std::make_unique<EventMessageWrite>(*this, std::move(t));

    event->prep();

    return static_cast<rawstor::io::Event*>(event.release());
}

void Queue::cancel(rawstor::io::Event* event) {
    io_uring_sync_cancel_reg req = {};
    req.addr = (__u64)event;
    req.fd = 0;
    req.flags = 0;
    int res = io_uring_register_sync_cancel(&_ring, &req);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

void Queue::wait(unsigned int timeout) {
    int res;
    io_uring_cqe* cqe;
    __kernel_timespec ts = {
        .tv_sec = timeout / 1000, .tv_nsec = 1000000u * (timeout % 1000)
    };

    while (true) {
        if (io_uring_sq_ready(&_ring) > 0) {
            /**
             * TODO: Replace with io_uring_submit_wait_cqe_timeout and do
             * something with sigmask.
             */
            res = io_uring_submit(&_ring);
            if (res < 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
            rawstor_trace("io_uring_wait_cqe_timeout()\n");
            res = io_uring_wait_cqe_timeout(&_ring, &cqe, &ts);
            rawstor_trace("io_uring_wait_cqe_timeout(): res = %d\n", res);
            if (res < 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        } else {
            rawstor_trace("io_uring_wait_cqe_timeout()\n");
            res = io_uring_wait_cqe_timeout(&_ring, &cqe, &ts);
            rawstor_trace("io_uring_wait_cqe_timeout(): res = %d\n", res);
            if (res < 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }
        std::unique_ptr<Event> event(
            static_cast<Event*>(io_uring_cqe_get_data(cqe))
        );

        event->set_result(cqe->res);

        io_uring_cqe_seen(&_ring, cqe);

        if (event->completed() || event->error() || cqe->res == 0) {
            event->dispatch();
            break;
        }

        event->prep();
        event.release();
    }
}

} // namespace uring
} // namespace io
} // namespace rawstor
