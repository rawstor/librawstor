#ifndef RAWSTORIO_TESTS_FIXTURE_HPP
#define RAWSTORIO_TESTS_FIXTURE_HPP

#include "server.hpp"

#include <rawstorio/queue.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <utility>

namespace rawstor {
namespace io {
namespace tests {

class QueueTest : public testing::Test {
protected:
    rawstor::io::tests::Server _server;
    Socket _socket;
    int _fd;
    std::unique_ptr<rawstor::io::Queue> _queue;

    QueueTest(unsigned int depth);

    void _wait_all();
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_FIXTURE_HPP
