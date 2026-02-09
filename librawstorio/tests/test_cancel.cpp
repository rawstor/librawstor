#include "config.h"
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

TEST_F(CancelTest, cancel_nullptr) {
    EXPECT_THROW(_queue->cancel(nullptr), std::system_error);
}

TEST_F(CancelTest, poll) {
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTask>(&result, &error);
        event = _queue->poll(_fd, POLLIN, std::move(t));
    }

    EXPECT_THROW(_queue->wait(0), std::system_error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait(0));
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
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTask>(&result, &error);
        event = _queue->poll(_fd, POLLIN, std::move(t));
    }

    _queue->wait(0);

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_EQ(result, (size_t)POLLIN);
    EXPECT_EQ(error, 0);
}

TEST_F(CancelTest, read) {
    char client_buf[10];
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTask>(&result, &error);
        event = _queue->read(_fd, client_buf, sizeof(client_buf), std::move(t));
    }

    EXPECT_THROW(_queue->wait(0), std::system_error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait(0));

    EXPECT_THROW(_queue->wait(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, read_completed) {
    const char server_buf[] = "data";
    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    {
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTask>(&result, &error);
        event = _queue->read(_fd, client_buf, sizeof(client_buf), std::move(t));
    }

    _queue->wait(0);

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
}

TEST_F(CancelTest, write) {
#ifdef RAWSTOR_WITH_LIBURING
    GTEST_SKIP() << "Async write cancelation is hard to test";
#endif

    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTask>(&result, &error);
        event =
            _queue->write(_fd, client_buf, sizeof(client_buf), std::move(t));
    }

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait(0));

    EXPECT_THROW(_queue->wait(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, write_completed) {
    char client_buf[] = "data";
    char server_buf[sizeof(client_buf)];
    size_t result = 0;
    int error = 0;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTask>(&result, &error);
        event =
            _queue->write(_fd, client_buf, sizeof(client_buf), std::move(t));
    }

    _queue->wait(0);

    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

} // unnamed namespace
