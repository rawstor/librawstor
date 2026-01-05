#include "server.hpp"

#include "fixture.hpp"
#include "task.hpp"

#include <rawstorstd/gpp.hpp>

#include <rawstorio/queue.hpp>

#include <gtest/gtest.h>

#include <unistd.h>

namespace {

class BasicsTest : public rawstor::io::tests::QueueTest {
protected:
    BasicsTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(BasicsTest, read) {
    const char server_buf[] = "data";
    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    std::unique_ptr<rawstor::io::TaskScalar> t =
        std::make_unique<rawstor::io::tests::SimpleTask>(
            _fd, client_buf, sizeof(client_buf), result, error
        );
    _queue->read(std::move(t));
    _queue->wait(0);

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strcmp(client_buf, server_buf), 0);
}

TEST_F(BasicsTest, write) {
    char client_buf[] = "data";
    char server_buf[sizeof(client_buf)];
    size_t result = 0;
    int error = 0;

    std::unique_ptr<rawstor::io::TaskScalar> t =
        std::make_unique<rawstor::io::tests::SimpleTask>(
            _fd, client_buf, sizeof(client_buf), result, error
        );
    _queue->write(std::move(t));
    _queue->wait(0);

    _server.read(sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result, sizeof(client_buf));
    EXPECT_EQ(error, 0);
    EXPECT_EQ(_server.buf_size(), sizeof(server_buf));
    EXPECT_EQ(strcmp(_server.buf(), client_buf), 0);
}

} // unnamed namespace
