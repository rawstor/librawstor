#include "fixture.hpp"

#include <rawstd/gpp.hpp>

#include <sys/socket.h>
#include <sys/un.h>

#include <memory>
#include <system_error>

namespace rawio {
namespace tests {

QueueTest::QueueTest(unsigned int depth) :
    testing::Test(),
    _server(),
    _queue(rawio::Queue::create(depth)) {
    _socket.connect(_server.socket());
    rawio::Queue::setup_fd(_socket.fd());
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
} // namespace rawio
