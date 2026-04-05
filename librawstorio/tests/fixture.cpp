#include "fixture.hpp"

#include <rawstorstd/gpp.hpp>

#include <sys/socket.h>
#include <sys/un.h>

#include <memory>
#include <system_error>

namespace rawstor {
namespace io {
namespace tests {

QueueTest::QueueTest(unsigned int depth) :
    testing::Test(),
    _server(),
    _queue(rawstor::io::Queue::create(depth)) {
    _socket.connect(_server.socket());
    rawstor::io::Queue::setup_fd(_socket.fd());
    _fd = _socket.fd();
}

void QueueTest::_wait_all() {
    try {
        while (true) {
            _queue->wait(0);
        }
    } catch (const std::system_error& e) {
        if (e.code().value() != ETIME) {
            throw;
        }
    }
}

} // namespace tests
} // namespace io
} // namespace rawstor
