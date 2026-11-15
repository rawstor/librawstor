#include "fixture.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/socket.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <system_error>

#include <sys/socket.h>
#include <unistd.h>

namespace {

rawstd::Task<int> shutdown_of(rawio::Queue& queue, int fd, int how) {
    co_return co_await queue.shutdown(fd, how);
}

rawstd::Task<size_t> receive(rawio::Queue& queue, int fd) {
    char buf[16];
    co_return co_await queue.recv(fd, buf, sizeof(buf), 0);
}

class ShutdownTest : public rawio::tests::QueueTest {
protected:
    int _fds[2] = {-1, -1};

    ShutdownTest() : rawio::tests::QueueTest(8) {}

    void SetUp() override {
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, _fds), 0);
        // What keeps the send() the tests make from raising SIGPIPE on
        // macOS, which has no flag for it.
        ASSERT_EQ(rawstd_socket_set_nosigpipe(_fds[0]), 0);
        ASSERT_EQ(rawstd_socket_set_nosigpipe(_fds[1]), 0);
        rawio::Queue::setup_fd(_fds[0]);
        rawio::Queue::setup_fd(_fds[1]);
    }

    void TearDown() override {
        for (int fd : _fds) {
            if (fd != -1) {
                ::close(fd);
            }
        }
    }

    template <typename T>
    bool drive(rawstd::Task<T>& task, unsigned int limit_ms = 3000) {
        std::chrono::steady_clock::time_point stop =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(limit_ms);
        while (!task.done() && std::chrono::steady_clock::now() < stop) {
            try {
                _queue->wait_timeout(10);
            } catch (const std::system_error& e) {
                if (e.code().value() != ETIME) {
                    throw;
                }
            }
        }
        return task.done();
    }

    template <typename T>
    static int error_of(rawstd::Task<T>& task) {
        try {
            task.get();
        } catch (const std::system_error& e) {
            return e.code().value();
        }
        return 0;
    }
};

TEST_F(ShutdownTest, write_side_ends_the_stream_of_the_peer) {
    rawstd::Task<int> t = shutdown_of(*_queue, _fds[0], SHUT_WR);
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(t.get(), 0);

    // The end of the stream, not "nothing yet" (EAGAIN) and not an error.
    char buf[1];
    EXPECT_EQ(recv(_fds[1], buf, sizeof(buf), MSG_DONTWAIT), 0);
    // Our own sending is over, and the peer's way back is open.
    EXPECT_EQ(send(_fds[0], "x", 1, RAWSTD_MSG_NOSIGNAL), -1);
    EXPECT_EQ(errno, EPIPE);
    EXPECT_EQ(send(_fds[1], "x", 1, RAWSTD_MSG_NOSIGNAL), 1);
}

TEST_F(ShutdownTest, pending_recv_completes_with_the_end_of_the_stream) {
    rawstd::Task<size_t> recv_task = receive(*_queue, _fds[0]);
    EXPECT_FALSE(drive(recv_task, 30));

    rawstd::Task<int> t = shutdown_of(*_queue, _fds[0], SHUT_RDWR);
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(t.get(), 0);

    // Not ECANCELED: the wait ended because the connection did.
    ASSERT_TRUE(drive(recv_task));
    EXPECT_EQ(recv_task.get(), (size_t)0);
}

TEST_F(ShutdownTest, bad_descriptor_fails) {
    rawstd::Task<int> t = shutdown_of(*_queue, -1, SHUT_RDWR);
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), EBADF);
}

TEST_F(ShutdownTest, socket_that_is_not_connected_fails_with_enotconn) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);

    rawstd::Task<int> t = shutdown_of(*_queue, fd, SHUT_RDWR);
    ASSERT_TRUE(drive(t));
    EXPECT_EQ(error_of(t), ENOTCONN);

    ::close(fd);
}

} // namespace
