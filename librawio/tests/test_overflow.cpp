#include "fixture.hpp"
#include "server.hpp"

#include <rawstd/coro.hpp>

#include <gtest/gtest.h>

namespace {

class OverflowTest : public rawio::tests::QueueTest {
protected:
    OverflowTest() : rawio::tests::QueueTest(2) {}
};

TEST_F(OverflowTest, push_three) {
    const char server_buf[] = "data1data2data3";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf1[5];
    size_t result1 = 0;
    rawstd::Task<void> t1;
    EXPECT_NO_THROW(
        t1 = rawio::tests::await_into(
            _queue->read(_fd, client_buf1, sizeof(client_buf1)), &result1
        )
    );

    char client_buf2[5];
    size_t result2 = 0;
    rawstd::Task<void> t2;
    EXPECT_NO_THROW(
        t2 = rawio::tests::await_into(
            _queue->read(_fd, client_buf2, sizeof(client_buf2)), &result2
        )
    );

    /*
     * The queue holds only two entries. The uring engine flushes the
     * backlog to the kernel and retries, so the third read succeeds; the
     * poll engine has a fixed pending list and fails with ENOBUFS.
     */
    char client_buf3[5];
    size_t result3 = 0;
    int error3 = 0;
    rawstd::Task<void> t3;
    if (rawio::Queue::engine_name() == "uring") {
        EXPECT_NO_THROW(
            t3 = rawio::tests::await_into(
                _queue->read(_fd, client_buf3, sizeof(client_buf3)), &result3,
                &error3
            )
        );
    } else {
        EXPECT_THROW(
            _queue->read(_fd, client_buf3, sizeof(client_buf3)),
            std::system_error
        );
    }

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result1, sizeof(client_buf1));
    EXPECT_EQ(strncmp(client_buf1, "data1", 5), 0);

    EXPECT_EQ(result2, sizeof(client_buf2));
    EXPECT_EQ(strncmp(client_buf2, "data2", 5), 0);

    if (rawio::Queue::engine_name() == "uring") {
        EXPECT_EQ(result3, sizeof(client_buf3));
        EXPECT_EQ(error3, 0);
        EXPECT_EQ(strncmp(client_buf3, "data3", 5), 0);
    } else {
        EXPECT_EQ(result3, (size_t)0);
        EXPECT_EQ(error3, 0);
    }
}

TEST_F(OverflowTest, push_two_pop_one) {
    const char server_buf[] = "data1data2data3";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf1[5];
    size_t result1 = 0;
    rawstd::Task<void> t1;
    EXPECT_NO_THROW(
        t1 = rawio::tests::await_into(
            _queue->read(_fd, client_buf1, sizeof(client_buf1)), &result1
        )
    );

    char client_buf2[5];
    size_t result2 = 0;
    rawstd::Task<void> t2;
    EXPECT_NO_THROW(
        t2 = rawio::tests::await_into(
            _queue->read(_fd, client_buf2, sizeof(client_buf2)), &result2
        )
    );

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result1, sizeof(client_buf1));
    EXPECT_EQ(strncmp(client_buf1, "data1", 5), 0);

    char client_buf3[5];
    size_t result3 = 0;
    rawstd::Task<void> t3;
    EXPECT_NO_THROW(
        t3 = rawio::tests::await_into(
            _queue->read(_fd, client_buf3, sizeof(client_buf3)), &result3
        )
    );

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result2, sizeof(client_buf2));
    EXPECT_EQ(strncmp(client_buf2, "data2", 5), 0);

    EXPECT_EQ(result3, sizeof(client_buf3));
    EXPECT_EQ(strncmp(client_buf3, "data3", 5), 0);
}

} // unnamed namespace
