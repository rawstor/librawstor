#include "fixture.hpp"
#include "server.hpp"

#include <gtest/gtest.h>

namespace {

class MultiplexTest : public rawio::tests::QueueTest {
protected:
    MultiplexTest() : rawio::tests::QueueTest(2) {}
};

TEST_F(MultiplexTest, read) {
    const char server_buf[] = "data1data2";
    _server.write(server_buf, 10);
    _server.wait();

    char client_buf1[5];
    size_t result1 = 0;
    rawstd::Task<void> t1 = rawio::tests::await_into(
        _queue->read(_fd, client_buf1, sizeof(client_buf1)), &result1
    );

    char client_buf2[5];
    size_t result2 = 0;
    rawstd::Task<void> t2 = rawio::tests::await_into(
        _queue->read(_fd, client_buf2, sizeof(client_buf2)), &result2
    );

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result1, (size_t)5);
    EXPECT_EQ(strncmp(client_buf1, "data1", 5), 0);

    EXPECT_EQ(result2, (size_t)5);
    EXPECT_EQ(strncmp(client_buf2, "data2", 5), 0);
}

TEST_F(MultiplexTest, write) {
    char client_buf1[] = "data1";
    size_t result1 = 0;
    rawstd::Task<void> t1 =
        rawio::tests::await_into(_queue->write(_fd, client_buf1, 5), &result1);

    char client_buf2[] = "data2";
    size_t result2 = 0;
    rawstd::Task<void> t2 =
        rawio::tests::await_into(_queue->write(_fd, client_buf2, 5), &result2);

    EXPECT_NO_THROW(_wait_all());

    char server_buf[10];
    _server.read(server_buf, sizeof(server_buf));
    _server.wait();

    EXPECT_EQ(result1, (size_t)5);
    EXPECT_EQ(result2, (size_t)5);

    EXPECT_EQ(strncmp(server_buf, "data1data2", sizeof(server_buf)), 0);
}

} // unnamed namespace
