#include "config.h"
#include "fixture.hpp"
#include "server.hpp"

#include <gtest/gtest.h>

#include <poll.h>

#include <system_error>

namespace {

class CancelTest : public rawio::tests::QueueTest {
protected:
    CancelTest() : rawio::tests::QueueTest(4) {}
};

TEST_F(CancelTest, cancel_noent) {
    EXPECT_THROW(_queue->cancel(nullptr), std::system_error);
    EXPECT_NO_THROW(_queue->cancel(0));
}

TEST_F(CancelTest, poll) {
    size_t result = 0;
    int error = 0;
    rawio::Event* event =
        _queue->poll(_fd, POLLIN, [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        });

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait_timeout(0));
    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, poll_completed) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    size_t result = 0;
    int error = 0;
    rawio::Event* event =
        _queue->poll(_fd, POLLIN, [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        });

    _queue->wait_timeout(0);

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_EQ(result, (size_t)POLLIN);
    EXPECT_EQ(error, 0);
}

TEST_F(CancelTest, read) {
    char client_buf[10];
    size_t result = 0;
    int error = 0;
    rawio::Event* event = _queue->read(
        _fd, client_buf, sizeof(client_buf),
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait_timeout(0));

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, read_completed) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;
    rawio::Event* event = _queue->read(
        _fd, client_buf, sizeof(client_buf),
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );

    _queue->wait_timeout(0);

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
}

TEST_F(CancelTest, write) {
#ifdef RAWIO_WITH_LIBURING
    GTEST_SKIP() << "Async write cancelation is hard to test";
#endif

    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    rawio::Event* event = nullptr;
    event = _queue->write(
        _fd, client_buf, sizeof(client_buf),
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait_timeout(0));

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, write_completed) {
    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    rawio::Event* event = _queue->write(
        _fd, client_buf, sizeof(client_buf),
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );
    _queue->wait_timeout(0);

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

TEST_F(CancelTest, cancel_all) {
    size_t result_poll = 0;
    int error_poll = 0;
    _queue->poll(_fd, POLLIN, [&result_poll, &error_poll](size_t r, int e) {
        result_poll = r;
        error_poll = e;
    });

    char client_buf_read[10];
    size_t result_read = 0;
    int error_read = 0;
    _queue->read(
        _fd, client_buf_read, sizeof(client_buf_read),
        [&result_read, &error_read](size_t r, int e) {
            result_read = r;
            error_read = e;
        }
    );

    char client_buf_write[] = "data";
    size_t result_write = 0;
    int error_write = 0;
    _queue->write(
        _fd, client_buf_write, sizeof(client_buf_write),
        [&result_write, &error_write](size_t r, int e) {
            result_write = r;
            error_write = e;
        }
    );

    _queue->cancel(_fd);

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result_poll, (size_t)0);
    EXPECT_EQ(error_poll, ECANCELED);
    EXPECT_EQ(result_read, (size_t)0);
    EXPECT_EQ(error_read, ECANCELED);
#ifndef RAWIO_WITH_LIBURING
    EXPECT_EQ(result_write, (size_t)0);
    EXPECT_EQ(error_write, ECANCELED);
#endif
}

} // unnamed namespace
