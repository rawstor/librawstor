#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

#include <poll.h>

#include <system_error>

namespace {

class CancelTest : public rawstor::io::tests::QueueTest {
protected:
    CancelTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(CancelTest, poll_nullptr) {
    EXPECT_THROW(_queue->cancel_poll(nullptr), std::system_error);
}

TEST_F(CancelTest, poll) {
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLIN, result, error
            );
        event = _queue->poll(std::move(t));
    }
    EXPECT_FALSE(_queue->empty());

    EXPECT_THROW(_queue->wait(0), std::system_error);

    _queue->cancel_poll(event);

    EXPECT_FALSE(_queue->empty());
    _queue->wait(0);
    EXPECT_TRUE(_queue->empty());
    EXPECT_THROW(_queue->wait(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, poll_completed) {
    const char server_buf[] = "data";
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLIN, result, error
            );
        event = _queue->poll(std::move(t));
    }
    _queue->wait(0);

    EXPECT_THROW(_queue->cancel_poll(event), std::system_error);
}

} // unnamed namespace
