#include "connection.hpp"

#include "opts.h"

#include <rawstorio/event.hpp>
#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>

#include <rawstor/object.h>

#include <stdexcept>

namespace rawstor {


Queue::Queue(int operations, unsigned int depth):
    _operations(operations),
    _q(rawstor::io::Queue::create(depth))
{}


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


void Queue::wait() {
    while (_operations > 0) {
        rawstor::io::Event *event = _q->wait_event(rawstor_opts_wait_timeout());
        if (event == NULL) {
            break;
        }

        event->dispatch();

        _q->release_event(event);
    }

    if (_operations > 0) {
        throw std::runtime_error("Queue not completed");
    }
}


} // rawstor
