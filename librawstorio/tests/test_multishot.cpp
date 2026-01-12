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

} // unnamed namespace
