#include "config.h"
#include "fixture.hpp"
#include "server.hpp"

#include <rawio/awaitable.hpp>
#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstring>

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
    // A short write is an entirely ordinary outcome for Queue::write(),
    // not a "still pending" one -- under io_uring in particular, a
    // handful of bytes into a fresh socket send buffer completes
    // synchronously as soon as it's polled, leaving cancel() nothing
    // still in flight to actually cancel. Filling the socket to
    // genuinely zero spare capacity first (synchronously, via a
    // temporarily non-blocking _fd) is the only way to guarantee the
    // write below has no room to make any progress and has to actually
    // suspend -- same technique as
    // cancel_fd_resolves_pending_write_before_close further down.
    int flags = fcntl(_fd, F_GETFL, 0);
    ASSERT_NE(flags, -1);
    ASSERT_EQ(fcntl(_fd, F_SETFL, flags | O_NONBLOCK), 0);

    std::vector<char> filler(1u << 20, 'f');
    while (true) {
        ssize_t n = ::write(_fd, filler.data(), filler.size());
        if (n < 0) {
            ASSERT_EQ(errno, EAGAIN) << strerror(errno);
            break;
        }
    }

    ASSERT_EQ(fcntl(_fd, F_SETFL, flags), 0);

    char client_buf[] = "data";
    size_t result = 0;
    int error = 0;
    rawio::Awaitable<size_t> aw =
        _queue->write(_fd, client_buf, sizeof(client_buf));
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

// Queue::close() (uring_queue.cpp) is a plain IORING_OP_CLOSE with no
// cancel-first step of its own, unlike ~Queue()'s own
// io_uring_register_sync_cancel() sweep at shutdown -- closing an fd
// that still has another op genuinely in flight on it (e.g. a
// pwritev()'s own write()/sendmsg() that hasn't completed yet) can leave
// that op's completion undelivered forever: its coroutine stays
// suspended with nothing left to ever resume it. This is exactly the
// "vhost lost-completion hang" shape (rawstor-vhost fully idle, a guest
// write stuck forever) live-reproduced under fio load against a real OST
// reconnect on 2026-08-29 -- root-caused down to this fd here.
//
// rawstor::Backend::close() (src/ost_backend.cpp) works around it by
// explicitly `co_await`ing `_queue.cancel(f)` -- cancelling everything
// else still outstanding on the fd -- before `_queue.close(f)`, in
// addition to its pre-existing `_queue.cancel(_read_event)` for its own
// recv-multishot stream. This test protects that specific sequence at
// the primitive level it depends on: without the cancel(fd) step, the
// second EXPECT_TRUE below fails (confirmed by temporarily dropping it
// while developing this fix); with it, the pending write reliably
// resolves.
TEST_F(CancelTest, cancel_fd_resolves_pending_write_before_close) {
    // A short write is an entirely ordinary outcome for Queue::write(),
    // not a "still pending" one -- filling the socket to genuinely zero
    // spare capacity first (synchronously, via a temporarily non-blocking
    // _fd) is the only way to guarantee the io_uring write below has no
    // room to make *any* progress and has to actually suspend, rather
    // than completing (however partially) as soon as it's polled.
    int flags = fcntl(_fd, F_GETFL, 0);
    ASSERT_NE(flags, -1);
    ASSERT_EQ(fcntl(_fd, F_SETFL, flags | O_NONBLOCK), 0);

    std::vector<char> filler(1u << 20, 'f');
    while (true) {
        ssize_t n = ::write(_fd, filler.data(), filler.size());
        if (n < 0) {
            ASSERT_EQ(errno, EAGAIN) << strerror(errno);
            break;
        }
    }

    ASSERT_EQ(fcntl(_fd, F_SETFL, flags), 0);

    char buf[] = "x";
    size_t result = 0;
    int error = 0;
    rawstd::Task<void> t_write = rawio::tests::await_into(
        _queue->write(_fd, buf, sizeof(buf)), &result, &error
    );

    // ETIME (nothing to reap within the budget) is the expected, ordinary
    // outcome here -- the whole point of filling the socket above is that
    // there is genuinely nothing for this to reap yet.
    auto pump = [this](unsigned int msec) {
        try {
            _queue->wait_timeout(msec);
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    };

    pump(0);
    ASSERT_FALSE(t_write.done())
        << "write finished on its own despite the socket buffer being "
           "filled to capacity just above -- this test isn't exercising "
           "the race it means to";

    // The fix under test: cancel everything else outstanding on the fd
    // *before* closing it, exactly like Session::close() now does.
    rawstd::Task<void> t_cancel = rawio::tests::wrap<void>(_queue->cancel(_fd));

    int close_result = 0;
    int close_error = 0;
    rawstd::Task<void> t_close = rawio::tests::await_into(
        _queue->close(_fd), &close_result, &close_error
    );

    // Bounded, not _wait_all()'s/run()'s unbounded pump: if the pending
    // write's completion really is lost, this must fail the test instead
    // of hanging the whole suite.
    for (int i = 0;
         i < 50 && !(t_write.done() && t_cancel.done() && t_close.done());
         ++i) {
        pump(10);
    }

    EXPECT_TRUE(t_cancel.done()) << "cancel(fd) itself never completed";
    EXPECT_TRUE(t_close.done()) << "close() itself never completed";
    EXPECT_TRUE(t_write.done()) << "write's own completion never arrived "
                                   "after cancel(fd) -- lost, exactly like "
                                   "the live vhost hang this test targets";
}

} // unnamed namespace
