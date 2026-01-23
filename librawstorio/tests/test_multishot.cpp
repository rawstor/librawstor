#include "fixture.hpp"
#include "server.hpp"
#include "task.hpp"

#include <gtest/gtest.h>

#include <poll.h>

namespace {

class MultishotTest : public rawstor::io::tests::QueueTest {
protected:
    MultishotTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(MultishotTest, poll) {
    const char server_buf[] = "data";
    size_t result = 0;
    int error = 0;
    unsigned int count = 0;
    rawstor::io::Event* event = nullptr;

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    {
        std::unique_ptr<rawstor::io::Task> t =
            std::make_unique<rawstor::io::tests::SimpleTaskMultishot>(
                &result, &error, &count
            );
        event = _queue->poll_multishot(_fd, std::move(t), POLLIN);
    }

    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)POLLIN);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(count, 1u);

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)POLLIN);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(count, 2u);

    EXPECT_NO_THROW(_queue->cancel(event));

    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
    EXPECT_EQ(count, 3u);
}

TEST_F(MultishotTest, recv) {
    {
        const char server_buf[] = "dat1dat2";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    char client_buf[5];
    size_t result;
    int error;
    unsigned int count;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskBuffered> t =
            std::make_unique<rawstor::io::tests::SimpleTaskBufferedMultishot>(
                client_buf, &result, &error, &count
            );
        event = _queue->recv_multishot(_fd, std::move(t), 4, 4, 0);
    }

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat1", 4), 0);
    EXPECT_EQ(count, 1u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat2", 4), 0);
    EXPECT_EQ(count, 2u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_THROW(_queue->wait(0), std::system_error);
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "", 4), 0);
    EXPECT_EQ(count, 2u);

    {
        const char server_buf[] = "dat3dat4";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat3", 4), 0);
    EXPECT_EQ(count, 3u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat4", 4), 0);
    EXPECT_EQ(count, 4u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_THROW(_queue->wait(0), std::system_error);
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "", 4), 0);
    EXPECT_EQ(count, 4u);

    EXPECT_NO_THROW(_queue->cancel(event));

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ECANCELED);
    EXPECT_EQ(count, 5u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_THROW(_queue->wait(0), std::system_error);
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "", 4), 0);
    EXPECT_EQ(count, 5u);
}

TEST_F(MultishotTest, recv_overflow) {
    {
        const char server_buf[] = "dat1dat2dat3dat4";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    char client_buf[5];
    size_t result;
    int error;
    unsigned int count;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskBuffered> t =
            std::make_unique<rawstor::io::tests::SimpleTaskBufferedMultishot>(
                client_buf, &result, &error, &count
            );
        event = _queue->recv_multishot(_fd, std::move(t), 4, 4, 0);
    }

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat1", 4), 0);
    EXPECT_EQ(count, 1u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat2", 4), 0);
    EXPECT_EQ(count, 2u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat3", 4), 0);
    EXPECT_EQ(count, 3u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)4);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "dat4", 4), 0);
    EXPECT_EQ(count, 4u);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, ENOBUFS);
    EXPECT_EQ(strncmp((char*)client_buf, "", 4), 0);
    EXPECT_EQ(count, 5u);

    EXPECT_THROW(_queue->cancel(event), std::system_error);

    memset(client_buf, '\0', 5);
    result = 0;
    error = 0;
    EXPECT_THROW(_queue->wait(0), std::system_error);
    EXPECT_EQ(result, (size_t)0);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(strncmp((char*)client_buf, "", 4), 0);
    EXPECT_EQ(count, 5u);
}

} // unnamed namespace
