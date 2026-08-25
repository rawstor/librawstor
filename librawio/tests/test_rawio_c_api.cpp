#include "fixture.hpp"

#include <rawstor/rawio.h>

#include <gtest/gtest.h>

#include <poll.h>

#include <cerrno>
#include <cstring>

namespace {

/**
 * The C shim (librawio/src/rawio.cpp) launches each op as a detached
 * coroutine: a nonzero return from the stored C completion callback is
 * meant to make the *original* rawio_wait()/rawio_wait_timeout() call
 * fail with that error (a real caller, ost/src/session.cpp's
 * io_callback(), relies on precisely this to propagate a business-logic
 * failure back out of the reactor loop). This is the one place a
 * DetachedTask could most easily end up silently swallowing the
 * exception instead (see rawstd::DetachedTask's doc comment) -- these
 * tests exercise the C ABI itself, not just the C++ rawio::Queue API
 * the rest of librawio/tests uses, to make sure the whole chain -- C
 * function pointer -> detached coroutine -> C++ exception -> C shim's
 * catch -> C return code -- still works end to end. rawio::Queue
 * publicly inherits RawIOQueue (include/rawio/queue.hpp), so
 * QueueTest's _queue converts to RawIOQueue* for free.
 */
class RawioCApiTest : public rawio::tests::QueueTest {
protected:
    RawioCApiTest() : rawio::tests::QueueTest(4) {}
};

int nonzero_return_cb(ssize_t result, void* data) {
    (void)result;
    (void)data;
    // A distinctive, unambiguous errno so a test failure can't be
    // confused with some other, unrelated -errno leaking through.
    return -EPROTO;
}

TEST_F(RawioCApiTest, write_callback_nonzero_return_propagates) {
    char buf[] = "data";
    int res = rawio_write2(
        _queue.get(), _fd, buf, sizeof(buf), nonzero_return_cb, nullptr
    );
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), -EPROTO);
}

TEST_F(RawioCApiTest, read_callback_nonzero_return_propagates) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf[sizeof(server_buf)];
    int res = rawio_read2(
        _queue.get(), _fd, client_buf, sizeof(client_buf), nonzero_return_cb,
        nullptr
    );
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), -EPROTO);
}

int counting_read_cb(ssize_t result, void* data) {
    int* count = static_cast<int*>(data);
    EXPECT_GT(result, 0);
    ++(*count);
    return 0;
}

TEST_F(RawioCApiTest, read_basic) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf[sizeof(server_buf)];
    int count = 0;
    int res = rawio_read2(
        _queue.get(), _fd, client_buf, sizeof(client_buf), counting_read_cb,
        &count
    );
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

// Backport shim coverage: rawio_write()/rawio_read() (old RawIOCallback
// shape -- separate `size_t result, int error` -- rather than
// rawio_write2()/rawio_read2()'s collapsed `ssize_t result`).
int legacy_write_cb(size_t result, int error, void* data) {
    bool* completed = static_cast<bool*>(data);
    EXPECT_EQ(error, 0);
    EXPECT_GT(result, (size_t)0);
    *completed = true;
    return 0;
}

int legacy_read_cb(size_t result, int error, void* data) {
    int* count = static_cast<int*>(data);
    EXPECT_EQ(error, 0);
    EXPECT_GT(result, (size_t)0);
    ++(*count);
    return 0;
}

TEST_F(RawioCApiTest, legacy_read_write_basic) {
    char buf[] = "legacy data";
    bool write_completed = false;
    int res = rawio_write(
        _queue.get(), _fd, buf, sizeof(buf), legacy_write_cb, &write_completed
    );
    ASSERT_EQ(res, 0);
    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_TRUE(write_completed);

    _server.wait();

    char server_buf[sizeof(buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();
    EXPECT_EQ(strcmp(server_buf, buf), 0);

    _server.write(buf, sizeof(buf));
    _server.wait();

    char client_buf[sizeof(buf)];
    int count = 0;
    res = rawio_read(
        _queue.get(), _fd, client_buf, sizeof(client_buf), legacy_read_cb,
        &count
    );
    ASSERT_EQ(res, 0);
    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(strcmp(client_buf, buf), 0);
}

int poll_multishot_count_cb(ssize_t result, void* data) {
    int* count = static_cast<int*>(data);
    // First delivery: real POLLIN readiness (non-negative). Second
    // delivery (post-cancel()): the terminal ECANCELED notification,
    // negative per rawio_poll_multishot2()'s raw-ssize_t convention.
    if (*count == 0) {
        EXPECT_GE(result, 0);
    } else {
        EXPECT_EQ(result, -ECANCELED);
    }
    ++(*count);
    return 0;
}

TEST_F(RawioCApiTest, poll_multishot_basic) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    int count = 0;
    RawIOEvent* event = nullptr;
    int res = rawio_poll_multishot2(
        _queue.get(), _fd, POLLIN, poll_multishot_count_cb, &count, &event
    );
    ASSERT_EQ(res, 0);
    ASSERT_NE(event, nullptr);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);

    EXPECT_EQ(rawio_cancel(_queue.get(), event), 0);
    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 2);
}

} // unnamed namespace
