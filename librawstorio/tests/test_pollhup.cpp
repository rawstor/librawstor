#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

#include <poll.h>

namespace {

class PollHupTest : public rawstor::io::tests::QueueTest {
protected:
    PollHupTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(PollHupTest, pollin) {
    const char server_buf[] = "data";
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, sizeof(server_buf));
    _server.close();
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLIN, result, error
            );
        _queue->poll(std::move(t));
    }
    _queue->wait(0);

    EXPECT_TRUE(result & POLLIN);
    EXPECT_TRUE(result & POLLHUP);
    EXPECT_EQ(error, 0);
}

TEST_F(PollHupTest, pollout) {
    size_t result = 0;
    int error = 0;

    _server.close();
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLOUT, result, error
            );
        _queue->poll(std::move(t));
    }
    _queue->wait(0);

    EXPECT_TRUE(result & POLLHUP);
    EXPECT_EQ(error, 0);
}

TEST_F(PollHupTest, read) {
    const char server_buf[] = "data1data2";
    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, 5);
    _server.close();
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                _fd, client_buf, 10, result, error
            );
        _queue->read(std::move(t));
    }
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)5);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp(client_buf, server_buf, 5), 0);
}

TEST_F(PollHupTest, write) {
    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;

    _server.close();
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                _fd, client_buf, sizeof(client_buf), result, error
            );
        _queue->write(std::move(t));
    }
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, EPIPE);
}

} // unnamed namespace
