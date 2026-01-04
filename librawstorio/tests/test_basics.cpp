#include "server.hpp"

#include <rawstorstd/gpp.hpp>

#include <rawstorio/queue.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>

namespace {

class BasicsTest : public testing::Test {
private:
    int _connect(const char* name) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        try {
            sockaddr_un addr = {};
            addr.sun_family = AF_UNIX;
            if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", name) <
                0) {
                RAWSTOR_THROW_ERRNO();
            }

            if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) ==
                -1) {
                RAWSTOR_THROW_ERRNO();
            }
        } catch (...) {
            close(fd);
            throw;
        }

        return fd;
    }

protected:
    rawstor::io::tests::Server _server;
    int _fd;
    std::unique_ptr<rawstor::io::Queue> _queue;

    BasicsTest() :
        _server(),
        _fd(_connect(_server.name())),
        _queue(rawstor::io::Queue::create(1)) {}
};

class SimpleTask final : public rawstor::io::TaskScalar {
private:
    void* _buf;
    size_t _size;

    size_t& _result;
    int& _error;

public:
    SimpleTask(int fd, void* buf, size_t size, size_t& result, int& error) :
        rawstor::io::TaskScalar(fd),
        _buf(buf),
        _size(size),
        _result(result),
        _error(error) {}

    void operator()(size_t result, int error) override {
        _result = result;
        _error = error;
    }

    void* buf() noexcept override { return _buf; }
    size_t size() const noexcept override { return _size; }
};

TEST_F(BasicsTest, read) {
    char buf[] = "data";
    size_t result = 0;
    int error = 0;

    _server.write(buf, sizeof(buf) - 1);
    _server.wait();

    std::unique_ptr<SimpleTask> t =
        std::make_unique<SimpleTask>(_fd, buf, sizeof(buf) - 1, result, error);
    _queue->read(std::move(t));
    _queue->wait(0);

    EXPECT_EQ(result, sizeof(buf) - 1);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp(static_cast<char*>(t->buf()), buf, sizeof(buf) - 1), 0);
}

TEST_F(BasicsTest, write) {
    char buf[] = "data";
    size_t result = 0;
    int error = 0;

    std::unique_ptr<SimpleTask> t =
        std::make_unique<SimpleTask>(_fd, buf, sizeof(buf) - 1, result, error);
    _queue->write(std::move(t));
    _queue->wait(0);

    _server.read(sizeof(buf) - 1);
    _server.wait();

    EXPECT_EQ(result, sizeof(buf) - 1);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(_server.buf_size(), sizeof(buf) - 1);
    EXPECT_EQ(strncmp(_server.buf(), buf, sizeof(buf) - 1), 0);
}

} // unnamed namespace
