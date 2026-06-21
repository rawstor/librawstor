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

    size_t result = 0;
    int error = 0;
    _queue->poll(_fd, POLLIN, [&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });

    EXPECT_NO_THROW(_queue->wait_timeout(0));

    EXPECT_THROW(_queue->wait_timeout(0), std::system_error);
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
    _queue->wait_timeout(0);

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
    _queue->wait_timeout(0);

    EXPECT_EQ(result, (size_t)POLLOUT);
    EXPECT_EQ(error, 0);
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

    size_t result = 0;
    int error = 0;
    _queue->accept(
        client_socket.fd(), nullptr, nullptr,
        [&result, &error](size_t r, int e) {
            result = r;
            error = e;
        }
    );

    EXPECT_NO_THROW(_queue->wait_timeout(0));
    EXPECT_GT(result, (size_t)0);
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
    _queue->wait_timeout(0);

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
    _queue->wait_timeout(0);

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
    _queue->wait_timeout(0);

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
    _queue->wait_timeout(0);

    char server_buf[sizeof(client_buf)];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
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
    queue->open(
        filename.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR,
        [&fd](int result) {
            fd = result;
        }
    );
    EXPECT_EQ(fd, -1);
    queue->wait();
    EXPECT_GT(fd, 0);

    queue->close(fd, [&fd](int result) { fd = result; });
    EXPECT_GT(fd, 0);
    queue->wait();
    EXPECT_EQ(fd, 0);
}

} // unnamed namespace
