#ifndef RAWIO_TESTS_FIXTURE_HPP
#define RAWIO_TESTS_FIXTURE_HPP

#include "server.hpp"

#include <rawio/queue.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <utility>

namespace rawio {
namespace tests {

class QueueTest : public testing::Test {
protected:
    rawio::tests::Server _server;
    Socket _socket;
    int _fd;
    std::unique_ptr<rawio::Queue> _queue;

    QueueTest(unsigned int depth);

    void _wait_all();
};

} // namespace tests
} // namespace rawio

#endif // RAWIO_TESTS_FIXTURE_HPP
