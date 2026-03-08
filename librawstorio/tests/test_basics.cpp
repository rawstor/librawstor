#include "fixture.hpp"
#include "server.hpp"

#include <gtest/gtest.h>

#include <poll.h>

namespace {

class BasicsTest : public rawstor::io::tests::QueueTest {
protected:
    BasicsTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(BasicsTest, empty) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();
    EXPECT_THROW(_queue->wait(0), std::system_error);

    size_t result = 0;
    int error = 0;
    _queue->poll(_fd, POLLIN, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });

    EXPECT_NO_THROW(_queue->wait(0));

    EXPECT_THROW(_queue->wait(0), std::system_error);
}

TEST_F(BasicsTest, pollin) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    size_t result = 0;
    int error = 0;
    _queue->poll(_fd, POLLIN, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)POLLIN);
    EXPECT_EQ(error, 0);
}

TEST_F(BasicsTest, pollout) {
    size_t result = 0;
    int error = 0;
    _queue->poll(_fd, POLLOUT, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });
    _queue->wait(0);

    EXPECT_EQ(result, (size_t)POLLOUT);
    EXPECT_EQ(error, 0);
}

TEST_F(BasicsTest, read) {
    const char server_buf[] = "data";
    char client_buf[sizeof(server_buf)];

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    size_t result = 0;
    int error = 0;
    _queue->read(
        _fd, client_buf, sizeof(client_buf),
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );
    _queue->wait(0);

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

TEST_F(BasicsTest, recv) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;
    _queue->recv(
        _fd, client_buf, sizeof(client_buf), 0,
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );
    _queue->wait(0);

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

TEST_F(BasicsTest, write) {
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

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

TEST_F(BasicsTest, send) {
    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    _queue->send(
        _fd, client_buf, sizeof(client_buf), 0,
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );
    _queue->wait(0);

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

} // unnamed namespace
