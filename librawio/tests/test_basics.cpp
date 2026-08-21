#include "fixture.hpp"
#include "server.hpp"

#include <rawstd/gpp.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <poll.h>

#include <filesystem>
#include <sstream>

namespace {

class BasicsTest : public rawio::tests::QueueTest {
protected:
    BasicsTest() : rawio::tests::QueueTest(1) {}
};

TEST_F(BasicsTest, empty) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();
    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);

    // Submitted but never co_await-ed: fire-and-forget, exercises that an
    // Awaitable<T> whose completion has no attached handle is a safe
    // no-op (see Queue::_attach()/resolve_one_shot()'s null checks).
    _queue->poll(_fd, POLLIN);

    EXPECT_NO_THROW(_queue->wait_timeout(0));

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);
}

TEST_F(BasicsTest, pollin) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    int result = 0;
    rawstd::Task<void> t =
        rawio::tests::await_into(_queue->poll(_fd, POLLIN), &result);
    _queue->wait_timeout(0);

    EXPECT_EQ(result, POLLIN);
}

TEST_F(BasicsTest, pollout) {
    int result = 0;
    rawstd::Task<void> t =
        rawio::tests::await_into(_queue->poll(_fd, POLLOUT), &result);
    _queue->wait_timeout(0);

    EXPECT_EQ(result, POLLOUT);
}

TEST_F(BasicsTest, accept) {
    rawio::tests::Socket client_socket;
    rawio::tests::Socket server_socket;

    client_socket.listen();

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s",
            client_socket.name().data()
        ) < 0) {
        RAWSTD_THROW_ERRNO();
    }

    _server.connect(
        server_socket.fd(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
    );
    _server.wait();

    int result = -1;
    rawstd::Task<void> t = rawio::tests::await_into(
        _queue->accept(client_socket.fd(), nullptr, nullptr), &result
    );

    EXPECT_NO_THROW(_queue->wait_timeout(0));
    EXPECT_GE(result, 0);
}

TEST_F(BasicsTest, read) {
    const char server_buf[] = "data";
    char client_buf[sizeof(server_buf)];

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    size_t result = 0;
    rawstd::Task<void> t = rawio::tests::await_into(
        _queue->read(_fd, client_buf, sizeof(client_buf)), &result
    );
    _queue->wait_timeout(0);

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

TEST_F(BasicsTest, recv) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    rawstd::Task<void> t = rawio::tests::await_into(
        _queue->recv(_fd, client_buf, sizeof(client_buf), 0), &result
    );
    _queue->wait_timeout(0);

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

TEST_F(BasicsTest, write) {
    char client_buf[] = "data";
    size_t result = 0;
    rawstd::Task<void> t = rawio::tests::await_into(
        _queue->write(_fd, client_buf, sizeof(client_buf)), &result
    );
    _queue->wait_timeout(0);

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

TEST_F(BasicsTest, send) {
    char client_buf[] = "data";
    size_t result = 0;
    rawstd::Task<void> t = rawio::tests::await_into(
        _queue->send(_fd, client_buf, sizeof(client_buf), 0), &result
    );
    _queue->wait_timeout(0);

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(strcmp(server_buf, client_buf), 0);
}

TEST(OpenCloseTest, basics) {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::ostringstream oss;
    std::filesystem::create_directory(path);
    oss << path.string() << "/open_close.test";
    std::string filename = oss.str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);

    int fd = -1;
    rawstd::Task<void> open_task = rawio::tests::await_into(
        queue->open(filename.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR),
        &fd
    );
    EXPECT_EQ(fd, -1);
    queue->wait();
    EXPECT_GT(fd, 0);

    rawstd::Task<void> close_task =
        rawio::tests::await_into(queue->close(fd), &fd);
    EXPECT_GT(fd, 0);
    queue->wait();
    EXPECT_EQ(fd, 0);
}

TEST(FsyncTest, basics) {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() / "rawio_tests";
    std::ostringstream oss;
    std::filesystem::create_directory(path);
    oss << path.string() << "/fsync.test";
    std::string filename = oss.str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);

    int fd = -1;
    rawstd::Task<void> open_task = rawio::tests::await_into(
        queue->open(filename.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR), &fd
    );
    queue->wait();
    ASSERT_GT(fd, 0);

    char buf[] = "data";
    size_t result = 0;
    rawstd::Task<void> pwrite_task = rawio::tests::await_into(
        queue->pwrite(fd, buf, sizeof(buf), 0, /*sync=*/true), &result
    );
    queue->wait();
    EXPECT_EQ(result, sizeof(buf));

    int fsync_result = -1;
    rawstd::Task<void> fsync_task = rawio::tests::await_into(
        queue->fsync(fd, /*datasync=*/true), &fsync_result
    );
    queue->wait();
    EXPECT_EQ(fsync_result, 0);

    // Fire-and-forget: nothing left in this test cares about close()'s
    // outcome.
    queue->close(fd);
    queue->wait();
}

TEST(ConnectTest, basics) {
    rawio::tests::Server server;

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(1);

    rawio::tests::Socket socket;

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s",
            server.socket().name().c_str()
        ) < 0) {
        RAWSTD_THROW_ERRNO();
    }

    int result = -1;
    rawstd::Task<void> t = rawio::tests::await_into(
        queue->connect(
            socket.fd(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
        ),
        &result
    );

    EXPECT_NO_THROW(queue->wait_timeout(0));
    EXPECT_GE(result, 0);
}

} // unnamed namespace
