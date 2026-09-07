#include "fixture.hpp"

#include <rawstor/rawio.h>

#include <gtest/gtest.h>

#include <sys/stat.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <filesystem>

#include <cerrno>
#include <cstdio>
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
    int res = rawio_write(
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
    int res = rawio_read(
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
    int res = rawio_read(
        _queue.get(), _fd, client_buf, sizeof(client_buf), counting_read_cb,
        &count
    );
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

int poll_multishot_count_cb(ssize_t result, void* data) {
    int* count = static_cast<int*>(data);
    // First delivery: real POLLIN readiness (non-negative). Second
    // delivery (post-cancel()): the terminal ECANCELED notification,
    // negative per rawio_poll_multishot()'s raw-ssize_t convention.
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
    int res = rawio_poll_multishot(
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

int timeout_count_cb(ssize_t result, void* data) {
    int* count = static_cast<int*>(data);
    EXPECT_EQ(result, 0);
    ++(*count);
    return 0;
}

TEST_F(RawioCApiTest, timeout_basic) {
    int count = 0;
    int res =
        rawio_timeout(_queue.get(), 20'000, timeout_count_cb, &count, nullptr);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);
}

int timeout_canceled_cb(ssize_t result, void* data) {
    int* count = static_cast<int*>(data);
    EXPECT_EQ(result, -ECANCELED);
    ++(*count);
    return 0;
}

TEST_F(RawioCApiTest, timeout_cancel) {
    int count = 0;
    RawIOEvent* event = nullptr;
    int res = rawio_timeout(
        _queue.get(), 1'000'000, timeout_canceled_cb, &count, &event
    );
    ASSERT_EQ(res, 0);
    ASSERT_NE(event, nullptr);

    // Not due yet, nothing else pending: an ordinary ETIME.
    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 0), -ETIME);

    EXPECT_EQ(rawio_cancel(_queue.get(), event), 0);
    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);
}

int timeout_multishot_count_cb(ssize_t result, void* data) {
    int* count = static_cast<int*>(data);
    // First two deliveries: ordinary ticks (0). Third (post-cancel): the
    // terminal ECANCELED notification.
    if (*count < 2) {
        EXPECT_EQ(result, 0);
    } else {
        EXPECT_EQ(result, -ECANCELED);
    }
    ++(*count);
    return 0;
}

TEST_F(RawioCApiTest, timeout_multishot_basic) {
    int count = 0;
    RawIOEvent* event = nullptr;
    int res = rawio_timeout_multishot(
        _queue.get(), 20'000, timeout_multishot_count_cb, &count, &event
    );
    ASSERT_EQ(res, 0);
    ASSERT_NE(event, nullptr);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 1);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 2);

    EXPECT_EQ(rawio_cancel(_queue.get(), event), 0);
    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(count, 3);
}

int result_cb(ssize_t result, void* data) {
    ssize_t* out = static_cast<ssize_t*>(data);
    *out = result;
    return 0;
}

TEST_F(RawioCApiTest, stat_basic) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::filesystem::create_directory(dir);
    std::string filename = (dir / "rawio_stat_c_api.test").string();

    const char buf[] = "data";
    FILE* f = fopen(filename.c_str(), "w");
    ASSERT_NE(f, nullptr);
    ASSERT_EQ(fwrite(buf, 1, sizeof(buf), f), sizeof(buf));
    fclose(f);

    struct stat st = {};
    ssize_t result = -1;
    int res =
        rawio_stat(_queue.get(), filename.c_str(), &st, result_cb, &result);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(st.st_size, static_cast<off_t>(sizeof(buf)));

    unlink(filename.c_str());
}

TEST_F(RawioCApiTest, stat_enoent) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::filesystem::create_directory(dir);
    std::string filename = (dir / "rawio_stat_c_api_missing.test").string();
    ASSERT_FALSE(std::filesystem::exists(filename));

    struct stat st = {};
    ssize_t result = 0;
    int res =
        rawio_stat(_queue.get(), filename.c_str(), &st, result_cb, &result);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(result, -ENOENT);
}

TEST_F(RawioCApiTest, fallocate_basic) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::filesystem::create_directory(dir);
    std::string filename = (dir / "rawio_fallocate_c_api.test").string();

    int fd = ::open(filename.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    ASSERT_GT(fd, 0);

    ssize_t result = -1;
    int res = rawio_fallocate(_queue.get(), fd, 0, 0, 4096, result_cb, &result);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(result, 0);

    struct stat st = {};
    ASSERT_EQ(fstat(fd, &st), 0);
    EXPECT_EQ(st.st_size, 4096);

    ::close(fd);
    unlink(filename.c_str());
}

TEST_F(RawioCApiTest, unlink_basic) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::filesystem::create_directory(dir);
    std::string filename = (dir / "rawio_unlink_c_api.test").string();

    FILE* f = fopen(filename.c_str(), "w");
    ASSERT_NE(f, nullptr);
    fclose(f);
    ASSERT_TRUE(std::filesystem::exists(filename));

    ssize_t result = 1;
    int res = rawio_unlink(_queue.get(), filename.c_str(), result_cb, &result);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(result, 0);
    EXPECT_FALSE(std::filesystem::exists(filename));
}

TEST_F(RawioCApiTest, unlink_enoent) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::filesystem::create_directory(dir);
    std::string filename = (dir / "rawio_unlink_c_api_missing.test").string();
    ASSERT_FALSE(std::filesystem::exists(filename));

    ssize_t result = 0;
    int res = rawio_unlink(_queue.get(), filename.c_str(), result_cb, &result);
    ASSERT_EQ(res, 0);

    EXPECT_EQ(rawio_wait_timeout(_queue.get(), 1000), 0);
    EXPECT_EQ(result, -ENOENT);
}

} // unnamed namespace
