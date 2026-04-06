#include "fixture.hpp"
#include "server.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/iovec.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <poll.h>

namespace {

class MultishotVectorItem {
private:
    std::vector<char> _data;
    const size_t _result;
    const int _error;

public:
    MultishotVectorItem(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) :
        _data(result),
        _result(result),
        _error(error) {
        if (result > 0) {
            rawstor_iovec_to_buf(iov, niov, 0, _data.data(), result);
        }
    }

    const char* data() const noexcept { return _data.data(); }
    size_t result() const noexcept { return _result; }
    int error() const noexcept { return _error; }
};

class MultishotTest : public rawstor::io::tests::QueueTest {
protected:
    MultishotTest() : rawstor::io::tests::QueueTest(1) {}
};

TEST_F(MultishotTest, poll) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    size_t result = 0;
    int error = 0;
    unsigned int count = 0;
    rawstor::io::Event* event = _queue->poll_multishot(
        _fd, POLLIN, [&result, &error, &count](size_t r, int e) {
            result = r;
            error = e;
            ++count;
        }
    );

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

TEST_F(MultishotTest, accept) {
    rawstor::io::tests::Socket client_socket;
    rawstor::io::tests::Socket server_socket1;
    rawstor::io::tests::Socket server_socket2;

    client_socket.listen();

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s",
            client_socket.name().data()
        ) < 0) {
        RAWSTOR_THROW_ERRNO();
    }

    _server.connect(
        server_socket1.fd(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
    );
    _server.wait();

    size_t result = 0;
    int error = 0;
    unsigned int count = 0;
    rawstor::io::Event* event = _queue->accept_multishot(
        client_socket.fd(),
        [&result, &error, &count](size_t r, int e) {
            result = r;
            error = e;
            ++count;
        }
    );

    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_GT(result, (size_t)0);
    EXPECT_EQ(error, 0);
    EXPECT_EQ(count, 1u);

    _server.connect(
        server_socket2.fd(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
    );
    _server.wait();

    result = 0;
    error = 0;
    EXPECT_NO_THROW(_queue->wait(0));
    EXPECT_GT(result, (size_t)0);
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
    const char server_buf[] = "dat1dat2";
    _server.write(server_buf, sizeof(server_buf) - 1);
    _server.wait();

    std::vector<MultishotVectorItem> items;
    rawstor::io::Event* event = _queue->recv_multishot(
        _fd, 4, 4, 4, 0,
        [&items](const iovec* iov, unsigned int niov, size_t result, int error)
            -> size_t {
            items.emplace_back(iov, niov, result, error);
            return 4;
        }
    );

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
        const char server_buf[] = "dat1dat2dat3dat4x";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    /**
     * NOTE: entry_size=4, entries=4 not working for uring in linux-6.11.0
     */
    std::vector<MultishotVectorItem> items;
    rawstor::io::Event* event = _queue->recv_multishot(
        _fd, 8, 2, 4, 0,
        [&items](const iovec* iov, unsigned int niov, size_t result, int error)
            -> size_t {
            items.emplace_back(iov, niov, result, error);
            return 4;
        }
    );

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
    std::vector<MultishotVectorItem> items;
    rawstor::io::Event* event = _queue->recv_multishot(
        _fd, 4, 4, 3, 0,
        [&items](const iovec* iov, unsigned int niov, size_t result, int error)
            -> size_t {
            items.emplace_back(iov, niov, result, error);
            return 3;
        }
    );

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
    std::vector<MultishotVectorItem> items;
    rawstor::io::Event* event = _queue->recv_multishot(
        _fd, 4, 4, 4, 0,
        [&items](const iovec* iov, unsigned int niov, size_t result, int error)
            -> size_t {
            items.emplace_back(iov, niov, result, error);
            return 4;
        }
    );

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

    EXPECT_NO_THROW(_wait_all());
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)1);
        EXPECT_EQ(items[4].error(), ECANCELED);
        EXPECT_EQ(strncmp(items[4].data(), "3", 1), 0);
    }
}

TEST_F(MultishotTest, stop_iteration) {
    {
        const char server_buf[] = "dat1dat2dat3";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    std::vector<MultishotVectorItem> items;
    rawstor::io::Event* event = _queue->recv_multishot(
        _fd, 8, 4, 4, 0,
        [&items](const iovec* iov, unsigned int niov, size_t result, int error)
            -> size_t {
            items.emplace_back(iov, niov, result, error);
            return 0;
        }
    );

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)1);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "dat1", 4), 0);
    }

    EXPECT_NO_THROW(_queue->cancel(event));

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)0);
        EXPECT_EQ(items[1].error(), ECANCELED);
    }
}

TEST_F(MultishotTest, stop_iteration_overflow) {
    {
        const char server_buf[] = "dat1dat2dat3";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    std::vector<MultishotVectorItem> items;
    rawstor::io::Event* event = _queue->recv_multishot(
        _fd, 8, 4, 4, 0,
        [&items](const iovec* iov, unsigned int niov, size_t result, int error)
            -> size_t {
            items.emplace_back(iov, niov, result, error);
            return 0;
        }
    );

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)1);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "dat1", 4), 0);
    }

    {
        const char server_buf[] = "dat4dat5dat6dat7dat8dat9";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)0);
        EXPECT_EQ(items[1].error(), ENOBUFS);
    }

    EXPECT_THROW(_queue->cancel(event), std::system_error);
    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)2);
}

} // unnamed namespace
