#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

#include <poll.h>

#include <system_error>

namespace {

class PartialTest : public rawstor::io::tests::QueueTest {
protected:
    PartialTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(PartialTest, read) {
    const char server_buf[] = "data1data2";
    char client_buf[sizeof(server_buf)];
    size_t result = 0;
    int error = 0;

    _server.write(server_buf, 5);
    _server.wait();

    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                _fd, client_buf, 10, result, error
            );
        _queue->read(std::move(t));
    }

    EXPECT_THROW(_queue->wait(0), std::system_error);

    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, 0);

    _server.write(server_buf + 5, 5);
    _server.wait();

    _queue->wait(0);

    EXPECT_EQ(result, (size_t)10);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp(client_buf, server_buf, 10), 0);
}

} // unnamed namespace
