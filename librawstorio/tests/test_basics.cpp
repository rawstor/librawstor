#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

#include <poll.h>

namespace {

class BasicsTest : public rawstor::io::tests::QueueTest {
protected:
    BasicsTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(BasicsTest, empty) {
    const char server_buf[] = "data";
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_TRUE(_queue->empty());
    EXPECT_THROW(_queue->wait(0), std::system_error);

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLIN, result, error
            );
        _queue->poll(std::move(t));
    }
    EXPECT_FALSE(_queue->empty());

    _queue->wait(0);

    EXPECT_TRUE(_queue->empty());
    EXPECT_THROW(_queue->wait(0), std::system_error);
}

TEST_F(BasicsTest, pollin) {
    const char server_buf[] = "data";
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLIN, result, error
            );
        _queue->poll(std::move(t));
    }
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)POLLIN);
    EXPECT_EQ(error, 0);
}

TEST_F(BasicsTest, pollout) {
    size_t result = 0;
    int error = 0;

    {
        std::unique_ptr<rawstor::io::TaskPoll> t =
            std::make_unique<rawstor::io::tests::SimplePollTask>(
                _fd, POLLOUT, result, error
            );
        _queue->poll(std::move(t));
    }
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)POLLOUT);
    EXPECT_EQ(error, 0);
}

TEST_F(BasicsTest, read) {
    const char server_buf[] = "data";
    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                _fd, client_buf, sizeof(client_buf), result, error
            );
        _queue->read(std::move(t));
    }
    _queue->wait(0);

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

TEST_F(BasicsTest, write) {
    char client_buf[] = "data";
    char server_buf[sizeof(client_buf)];
    size_t result = 0;
    int error = 0;

    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                _fd, client_buf, sizeof(client_buf), result, error
            );
        _queue->write(std::move(t));
    }
    _queue->wait(0);

    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

} // unnamed namespace
