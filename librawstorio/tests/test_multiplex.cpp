#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

namespace {

class MultiplexTest : public rawstor::io::tests::QueueTest {
protected:
    MultiplexTest() : rawstor::io::tests::QueueTest(2) {}
};

TEST_F(MultiplexTest, read) {
    const char server_buf[] = "data1data2";
    _server.write(server_buf, 10);
    _server.wait();

    char client_buf1[5];
    size_t result1 = 0;
    int error1 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf1, sizeof(client_buf1), result1, error1
            );
        _queue->read(_fd, std::move(t));
    }

    char client_buf2[5];
    size_t result2 = 0;
    int error2 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf2, sizeof(client_buf2), result2, error2
            );
        _queue->read(_fd, std::move(t));
    }

    _queue->wait(0);
    _queue->wait(0);

    EXPECT_EQ(result1, (size_t)5);
    EXPECT_EQ(error1, 0);
    EXPECT_EQ(strncmp(client_buf1, "data1", 5), 0);

    EXPECT_EQ(result2, (size_t)5);
    EXPECT_EQ(error2, 0);
    EXPECT_EQ(strncmp(client_buf2, "data2", 5), 0);
}

TEST_F(MultiplexTest, write) {
    char client_buf1[] = "data1";
    size_t result1 = 0;
    int error1 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf1, 5, result1, error1
            );
        _queue->write(_fd, std::move(t));
    }

    char client_buf2[] = "data2";
    size_t result2 = 0;
    int error2 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf2, 5, result2, error2
            );
        _queue->write(_fd, std::move(t));
    }

    _queue->wait(0);
    _queue->wait(0);

    char server_buf[10];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result1, (size_t)5);
    EXPECT_EQ(error1, 0);

    EXPECT_EQ(result2, (size_t)5);
    EXPECT_EQ(error2, 0);

    EXPECT_EQ(strncmp(server_buf, "data1data2", sizeof(server_buf)), 0);
}

} // unnamed namespace
