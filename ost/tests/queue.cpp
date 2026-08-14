#include "queue.hpp"

#include <rawstd/gpp.hpp>

namespace rawstor {
namespace ostbackend {
namespace tests {

Queue::Queue() : _queue(nullptr) {
    int res = rawio_queue_create(256, &_queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

Queue::~Queue() {
    rawio_queue_delete(_queue);
}

} // namespace tests
} // namespace ostbackend
} // namespace rawstor
