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

    std::vector<rawstor::io::tests::SimpleTaskVectorExternalItem> items;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskVectorExternal> t =
            std::make_unique<rawstor::io::tests::SimpleTaskVectorExternal>(
                4, &items
            );
        event = _queue->recv_multishot(_fd, std::move(t), 4, 4, 0);
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "dat1", 4), 0);
    }
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)4);
        EXPECT_EQ(items[1].error(), 0);
        EXPECT_EQ(strncmp(items[1].data(), "dat2", 4), 0);
    }

    {
        const char server_buf[] = "dat3dat4";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)4);
    if (items.size() >= 3) {
        EXPECT_EQ(items[2].result(), (size_t)4);
        EXPECT_EQ(items[2].error(), 0);
        EXPECT_EQ(strncmp(items[2].data(), "dat3", 4), 0);
    }
    if (items.size() >= 4) {
        EXPECT_EQ(items[3].result(), (size_t)4);
        EXPECT_EQ(items[3].error(), 0);
        EXPECT_EQ(strncmp(items[3].data(), "dat4", 4), 0);
    }

    EXPECT_NO_THROW(_queue->cancel(event));

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)5);
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)0);
        EXPECT_EQ(items[4].error(), ECANCELED);
    }

    EXPECT_THROW(_queue->wait(0), std::system_error);
    EXPECT_EQ(items.size(), (size_t)5);
}

TEST_F(MultishotTest, recv_overflow) {
    {
        const char server_buf[] = "dat1dat2dat3dat4";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    std::vector<rawstor::io::tests::SimpleTaskVectorExternalItem> items;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskVectorExternal> t =
            std::make_unique<rawstor::io::tests::SimpleTaskVectorExternal>(
                4, &items
            );
        event = _queue->recv_multishot(_fd, std::move(t), 8, 4, 0);
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)5);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "dat1", 4), 0);
    }
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)4);
        EXPECT_EQ(items[1].error(), 0);
        EXPECT_EQ(strncmp(items[1].data(), "dat2", 4), 0);
    }
    if (items.size() >= 3) {
        EXPECT_EQ(items[2].result(), (size_t)4);
        EXPECT_EQ(items[2].error(), 0);
        EXPECT_EQ(strncmp(items[2].data(), "dat3", 4), 0);
    }
    if (items.size() >= 4) {
        EXPECT_EQ(items[3].result(), (size_t)4);
        EXPECT_EQ(items[3].error(), 0);
        EXPECT_EQ(strncmp(items[3].data(), "dat4", 4), 0);
    }
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)0);
        EXPECT_EQ(items[4].error(), ENOBUFS);
    }

    EXPECT_THROW(_queue->cancel(event), std::system_error);

    EXPECT_THROW(_queue->wait(0), std::system_error);
    EXPECT_EQ(items.size(), (size_t)5);
}

TEST_F(MultishotTest, recv_partial) {
    std::vector<rawstor::io::tests::SimpleTaskVectorExternalItem> items;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskVectorExternal> t =
            std::make_unique<rawstor::io::tests::SimpleTaskVectorExternal>(
                3, &items
            );
        event = _queue->recv_multishot(_fd, std::move(t), 4, 4, 0);
    }

    {
        const char server_buf[] = "1234";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)1);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)3);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "123", 3), 0);
    }

    {
        const char server_buf[] = "5678";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)3);
        EXPECT_EQ(items[1].error(), 0);
        EXPECT_EQ(strncmp(items[1].data(), "456", 3), 0);
    }

    {
        const char server_buf[] = "90123";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)4);
    if (items.size() >= 3) {
        EXPECT_EQ(items[2].result(), (size_t)3);
        EXPECT_EQ(items[2].error(), 0);
        EXPECT_EQ(strncmp(items[2].data(), "789", 3), 0);
    }
    if (items.size() >= 4) {
        EXPECT_EQ(items[3].result(), (size_t)3);
        EXPECT_EQ(items[3].error(), 0);
        EXPECT_EQ(strncmp(items[3].data(), "012", 3), 0);
    }

    EXPECT_NO_THROW(_queue->cancel(event));

    EXPECT_NO_THROW(_queue->wait(0));
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)1);
        EXPECT_EQ(items[4].error(), ECANCELED);
        EXPECT_EQ(strncmp(items[4].data(), "3", 1), 0);
    }
}

TEST_F(MultishotTest, recv_fill_buf) {
    std::vector<rawstor::io::tests::SimpleTaskVectorExternalItem> items;
    rawstor::io::Event* event = nullptr;

    {
        std::unique_ptr<rawstor::io::TaskVectorExternal> t =
            std::make_unique<rawstor::io::tests::SimpleTaskVectorExternal>(
                4, &items
            );
        event = _queue->recv_multishot(_fd, std::move(t), 4, 4, 0);
    }

    {
        const char server_buf[] = "123";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)0);

    {
        const char server_buf[] = "456";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)1);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "1234", 3), 0);
    }

    {
        const char server_buf[] = "789";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)4);
        EXPECT_EQ(items[1].error(), 0);
        EXPECT_EQ(strncmp(items[1].data(), "5678", 3), 0);
    }

    {
        const char server_buf[] = "012";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)3);
    if (items.size() >= 3) {
        EXPECT_EQ(items[2].result(), (size_t)4);
        EXPECT_EQ(items[2].error(), 0);
        EXPECT_EQ(strncmp(items[2].data(), "9012", 3), 0);
    }

    EXPECT_NO_THROW(_queue->cancel(event));

    EXPECT_NO_THROW(_queue->wait(0));
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)1);
        EXPECT_EQ(items[4].error(), ECANCELED);
        EXPECT_EQ(strncmp(items[4].data(), "3", 1), 0);
    }
}

} // unnamed namespace
