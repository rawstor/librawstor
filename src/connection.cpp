#include "connection.hpp"

#include "opts.h"

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>

#include <rawstor/object.h>

#include <stdexcept>

namespace rawstor {


Queue::Queue(int operations, unsigned int depth):
    _operations(operations),
    _impl(nullptr)
{
    _impl = rawstor_io_queue_create(depth);
    if (_impl == nullptr) {
        RAWSTOR_THROW_ERRNO();
    }
}

Queue::~Queue() {
    rawstor_io_queue_delete(_impl);
}


int Queue::callback(
    RawstorObject *,
    size_t size, size_t res, int error, void *data) noexcept
{
    Queue *queue = static_cast<Queue*>(data);

    --queue->_operations;

    if (error) {
        return -error;
    }

    if (size != res) {
        return -EIO;
    }

    return 0;
}


Queue::operator RawstorIOQueue*() noexcept {
    return _impl;
}


void Queue::wait() {
    while (_operations > 0) {
        RawstorIOEvent *event = rawstor_io_queue_wait_event_timeout(
            _impl, rawstor_opts_wait_timeout());
        if (event == NULL) {
            if (errno) {
                RAWSTOR_THROW_ERRNO();
            }
            break;
        }

        int res = rawstor_io_event_dispatch(event);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        rawstor_io_queue_release_event(_impl, event);
    }

    if (_operations > 0) {
        throw std::runtime_error("Queue not completed");
    }
}


} // rawstor
