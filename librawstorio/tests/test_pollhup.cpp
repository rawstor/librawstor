#include "fixture.hpp"
#include "server.hpp"

#include <gtest/gtest.h>

#include <poll.h>

namespace {

class PollHupTest : public rawstor::io::tests::QueueTest {
protected:
    PollHupTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(PollHupTest, pollin) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.close();
    _server.wait();

    size_t result = 0;
    int error = 0;
    _queue->poll(_fd, POLLIN, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });
    _queue->wait(0);

    EXPECT_TRUE(result & POLLIN);
    EXPECT_TRUE(result & POLLHUP);
    EXPECT_EQ(error, 0);
}

TEST_F(PollHupTest, pollout) {
    _server.close();
    _server.wait();

    size_t result = 0;
    int error = 0;
    _queue->poll(_fd, POLLOUT, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });
    _queue->wait(0);

    EXPECT_TRUE(result & POLLHUP);
    EXPECT_EQ(error, 0);
}

TEST_F(PollHupTest, read) {
    const char server_buf[] = "data1data2";
    _server.write(server_buf, 5);
    _server.close();
    _server.wait();

    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;
    _queue->read(_fd, client_buf, 10, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)5);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp(client_buf, server_buf, 5), 0);
}

TEST_F(PollHupTest, write) {
    _server.close();
    _server.wait();

    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    _queue->write(
        _fd, client_buf, sizeof(client_buf),
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, EPIPE);
}

} // unnamed namespace
