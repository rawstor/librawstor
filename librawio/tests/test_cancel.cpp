#include "config.h"
#include "fixture.hpp"
#include "server.hpp"

#include <rawio/awaitable.hpp>
#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <poll.h>

#include <system_error>
#include <utility>

namespace {

class CancelTest : public rawio::tests::QueueTest {
protected:
    CancelTest() : rawio::tests::QueueTest(4) {}
};

TEST_F(CancelTest, cancel_noent) {
    // cancel() is fire-and-forget: targeting an already-gone/unknown event
    // or fd is an entirely ordinary outcome, not a failure -- see
    // rawio::Queue::cancel()'s doc comment.
    EXPECT_NO_THROW(_queue->cancel(nullptr));
    EXPECT_NO_THROW(_queue->cancel(0));
}

TEST_F(CancelTest, poll) {
    int result = 0;
    int error = 0;
    rawio::Awaitable<int> aw = _queue->poll(_fd, POLLIN);
    rawio::Event* event = aw.event();
    rawstd::Task<void> t =
        rawio::tests::await_into(std::move(aw), &result, &error);

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait_timeout(0));
    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    EXPECT_EQ(result, 0);
    EXPECT_EQ(error, ECANCELED);
}

// cancel() is normally fire-and-forget (every other test here just
// discards its return value, exactly like a destructor would), but it
// returns an ordinary Awaitable<void> like every other op, so it can be
// co_await-ed too -- verify that path actually resumes instead of hanging.
TEST_F(CancelTest, cancel_awaited) {
    int result = 0;
    int error = 0;
    rawio::Awaitable<int> aw = _queue->poll(_fd, POLLIN);
    rawio::Event* event = aw.event();
    rawstd::Task<void> t =
        rawio::tests::await_into(std::move(aw), &result, &error);

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    EXPECT_NO_THROW(
        rawio::tests::run(
            *_queue, rawio::tests::wrap<void>(_queue->cancel(event))
        )
    );

    EXPECT_EQ(result, 0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, poll_completed) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    int result = 0;
    rawio::Awaitable<int> aw = _queue->poll(_fd, POLLIN);
    rawio::Event* event = aw.event();
    rawstd::Task<void> t = rawio::tests::await_into(std::move(aw), &result);

    _queue->wait_timeout(0);

    EXPECT_NO_THROW(_queue->cancel(event));
    EXPECT_EQ(result, POLLIN);
}

TEST_F(CancelTest, read) {
    char client_buf[10];
    size_t result = 0;
    int error = 0;
    rawio::Awaitable<size_t> aw =
        _queue->read(_fd, client_buf, sizeof(client_buf));
    rawio::Event* event = aw.event();
    rawstd::Task<void> t =
        rawio::tests::await_into(std::move(aw), &result, &error);

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
    rawio::Awaitable<size_t> aw =
        _queue->read(_fd, client_buf, sizeof(client_buf));
    rawio::Event* event = aw.event();
    rawstd::Task<void> t = rawio::tests::await_into(std::move(aw), &result);

    _queue->wait_timeout(0);

    EXPECT_NO_THROW(_queue->cancel(event));
    EXPECT_EQ(result, sizeof(client_buf));
}

TEST_F(CancelTest, write) {
#ifdef RAWIO_WITH_LIBURING
    GTEST_SKIP() << "Async write cancelation is hard to test";
#endif

    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    rawio::Awaitable<size_t> aw =
        _queue->write(_fd, client_buf, sizeof(client_buf));
    rawio::Event* event = aw.event();
    rawstd::Task<void> t =
        rawio::tests::await_into(std::move(aw), &result, &error);

    _queue->cancel(event);

    EXPECT_NO_THROW(_queue->wait_timeout(0));

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
}

TEST_F(CancelTest, write_completed) {
    char client_buf[] = "data";
    size_t result = 0;
    rawio::Awaitable<size_t> aw =
        _queue->write(_fd, client_buf, sizeof(client_buf));
    rawio::Event* event = aw.event();
    rawstd::Task<void> t = rawio::tests::await_into(std::move(aw), &result);
    _queue->wait_timeout(0);

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_NO_THROW(_queue->cancel(event));
    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

TEST_F(CancelTest, cancel_all) {
    int result_poll = 0;
    int error_poll = 0;
    rawstd::Task<void> t_poll = rawio::tests::await_into(
        _queue->poll(_fd, POLLIN), &result_poll, &error_poll
    );

    char client_buf_read[10];
    size_t result_read = 0;
    int error_read = 0;
    rawstd::Task<void> t_read = rawio::tests::await_into(
        _queue->read(_fd, client_buf_read, sizeof(client_buf_read)),
        &result_read, &error_read
    );

    char client_buf_write[] = "data";
    size_t result_write = 0;
    int error_write = 0;
    rawstd::Task<void> t_write = rawio::tests::await_into(
        _queue->write(_fd, client_buf_write, sizeof(client_buf_write)),
        &result_write, &error_write
    );

    _queue->cancel(_fd);

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result_poll, 0);
    EXPECT_EQ(error_poll, ECANCELED);
    EXPECT_EQ(result_read, (size_t)0);
    EXPECT_EQ(error_read, ECANCELED);
#ifndef RAWIO_WITH_LIBURING
    EXPECT_EQ(result_write, (size_t)0);
    EXPECT_EQ(error_write, ECANCELED);
#endif
}

} // unnamed namespace
