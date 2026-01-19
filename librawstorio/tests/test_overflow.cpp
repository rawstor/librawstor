#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

namespace {

class OverflowTest : public rawstor::io::tests::QueueTest {
protected:
    OverflowTest() : rawstor::io::tests::QueueTest(2) {}
};

TEST_F(OverflowTest, push_three) {
    const char server_buf[] = "data1data2data3";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf1[5];
    size_t result1 = 0;
    int error1 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf1, sizeof(client_buf1), result1, error1
            );
        EXPECT_NO_THROW(_queue->read(_fd, std::move(t)));
    }

    char client_buf2[5];
    size_t result2 = 0;
    int error2 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf2, sizeof(client_buf2), result2, error2
            );
        EXPECT_NO_THROW(_queue->read(_fd, std::move(t)));
    }

    char client_buf3[5];
    size_t result3 = 0;
    int error3 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf3, sizeof(client_buf3), result3, error3
            );
        EXPECT_THROW(_queue->read(_fd, std::move(t)), std::system_error);
    }

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result1, sizeof(client_buf1));
    EXPECT_EQ(error1, 0);
    EXPECT_EQ(strncmp(client_buf1, "data1", 5), 0);

    EXPECT_EQ(result2, sizeof(client_buf2));
    EXPECT_EQ(error2, 0);
    EXPECT_EQ(strncmp(client_buf2, "data2", 5), 0);

    EXPECT_EQ(result3, (size_t)0);
    EXPECT_EQ(error3, 0);
}

TEST_F(OverflowTest, push_two_pop_one) {
    const char server_buf[] = "data1data2data3";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    char client_buf1[5];
    size_t result1 = 0;
    int error1 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf1, sizeof(client_buf1), result1, error1
            );
        EXPECT_NO_THROW(_queue->read(_fd, std::move(t)));
    }

    char client_buf2[5];
    size_t result2 = 0;
    int error2 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf2, sizeof(client_buf2), result2, error2
            );
        EXPECT_NO_THROW(_queue->read(_fd, std::move(t)));
    }

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result1, sizeof(client_buf1));
    EXPECT_EQ(error1, 0);
    EXPECT_EQ(strncmp(client_buf1, "data1", 5), 0);

    char client_buf3[5];
    size_t result3 = 0;
    int error3 = 0;
    {
        std::unique_ptr<rawstor::io::TaskScalar> t =
            std::make_unique<rawstor::io::tests::SimpleScalarTask>(
                client_buf3, sizeof(client_buf3), result3, error3
            );
        EXPECT_NO_THROW(_queue->read(_fd, std::move(t)));
    }

    EXPECT_NO_THROW(_wait_all());

    EXPECT_EQ(result2, sizeof(client_buf2));
    EXPECT_EQ(error2, 0);
    EXPECT_EQ(strncmp(client_buf2, "data2", 5), 0);

    EXPECT_EQ(result3, sizeof(client_buf3));
    EXPECT_EQ(error3, 0);
    EXPECT_EQ(strncmp(client_buf3, "data3", 5), 0);
}

} // unnamed namespace
