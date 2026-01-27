#ifndef RAWSTORIO_TESTS_FIXTURE_HPP
#define RAWSTORIO_TESTS_FIXTURE_HPP

#include "server.hpp"

#include <rawstorstd/gpp.hpp>

#include <rawstorio/queue.hpp>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <memory>
#include <system_error>

namespace rawstor {
namespace io {
namespace tests {

class QueueTest : public testing::Test {
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

        rawstor::io::Queue::setup_fd(fd);

        return fd;
    }

protected:
    rawstor::io::tests::Server _server;
    int _fd;
    std::unique_ptr<rawstor::io::Queue> _queue;

    QueueTest(unsigned int depth) :
        testing::Test(),
        _server(),
        _fd(_connect(_server.name())),
        _queue(rawstor::io::Queue::create(depth)) {}
    ~QueueTest() { close(_fd); }

    void _wait_all() {
        try {
            while (true) {
                _queue->wait(0);
            }
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_FIXTURE_HPP
