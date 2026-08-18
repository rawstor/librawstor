#include "fixture.hpp"
#include "server.hpp"

#include <rawio/stream.hpp>
#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/socket.h>

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <poll.h>
#include <unistd.h>

#include <system_error>

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
            rawstd_iovec_to_buf(iov, niov, 0, _data.data(), result);
        }
    }

    const char* data() const noexcept { return _data.data(); }
    size_t result() const noexcept { return _result; }
    int error() const noexcept { return _error; }
};

// Pulls exactly one item from `stream` and appends it to `items` -- a
// terminal error becomes a zero-result item carrying that error.
void pull(
    rawio::Queue& q, rawio::RecvStream& stream, size_t want,
    std::vector<MultishotVectorItem>& items
) {
    try {
        rawio::RecvStream::Item item = rawio::tests::run(
            q, rawio::tests::wrap<rawio::RecvStream::Item>(stream.next(want))
        );
        items.emplace_back(item.iov(), item.niov(), item.size(), 0);
    } catch (const std::system_error& e) {
        items.emplace_back(nullptr, 0, 0, e.code().value());
    }
}

class MultishotTest : public rawio::tests::QueueTest {
protected:
    MultishotTest() : rawio::tests::QueueTest(1) {}
};

class MultishotBurstTest : public rawio::tests::QueueTest {
protected:
    // A generously-sized queue: this test's whole point is to pile up a
    // burst of writes before they can be drained, and MultishotTest's
    // depth (sized for the other, low-volume multishot tests) is nowhere
    // near big enough not to overflow under that load.
    MultishotBurstTest() : rawio::tests::QueueTest(512) {}
};

TEST_F(MultishotTest, poll) {
    const char server_buf[] = "data";
    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    rawio::PollStream stream = _queue->poll_multishot(_fd, POLLIN);

    int result =
        rawio::tests::run(*_queue, rawio::tests::wrap<int>(stream.next()));
    EXPECT_EQ(result, POLLIN);

    _server.write(server_buf, sizeof(server_buf));
    _server.wait();

    result = rawio::tests::run(*_queue, rawio::tests::wrap<int>(stream.next()));
    EXPECT_EQ(result, POLLIN);

    rawio::Event* event = stream.event();
    EXPECT_NO_THROW(_queue->cancel(event));

    try {
        rawio::tests::run(*_queue, rawio::tests::wrap<int>(stream.next()));
        FAIL() << "expected ECANCELED";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

// Regression test for a same-batch duplicate poll_multishot wakeup landing
// on a coalescing resource (a pipe): a burst of writes before the
// registration gets a chance to drain any of them can make the backend
// observe "readable" more than once for writes that a single drain
// already accounts for in full. A caller that -- like libvhost-user's
// vu_kick_cb() -- treats every wakeup as carrying data to read would see
// a torn, empty read (EAGAIN) on the redundant one.
TEST_F(MultishotBurstTest, poll_pipe_burst_no_torn_read) {
    static constexpr unsigned int total_writes = 64;

    int fds[2];
    ASSERT_EQ(::pipe(fds), 0);
    int read_fd = fds[0];
    int write_fd = fds[1];
    ASSERT_EQ(rawstd_socket_set_nonblock(read_fd), 0);

    bool torn_read = false;
    unsigned int total_reads = 0;

    rawio::PollStream stream = _queue->poll_multishot(read_fd, POLLIN);
    rawio::Event* event = stream.event();

    // poll_multishot() only prepares the SQE locally; it isn't actually
    // submitted to the kernel until the next wait()/wait_timeout() call.
    // Force that submission now, while the pipe is still empty, so the
    // registration is live and armed in the kernel *before* any of the
    // writes below happen -- otherwise every write would land before the
    // poll request even exists and there would be nothing to race.
    EXPECT_NO_THROW(_wait_all());

    // Pile up every write *before* the registration gets a chance to
    // drain any of them. That's deliberate and deterministic (no racing
    // against a second thread's scheduling): each write() wakes the poll
    // waitqueue regardless of whether anything drained the previous one,
    // so by the time we drain below, the kernel has as many "became
    // readable" wakeups queued up for this one registration as it's
    // going to get from this burst -- exactly the condition a bursty
    // real kicker produces, just guaranteed instead of hoped for.
    for (unsigned int i = 0; i < total_writes; ++i) {
        char one = 1;
        ASSERT_EQ(::write(write_fd, &one, sizeof(one)), (ssize_t)sizeof(one));
    }

    // Unlike the _wait_all() calls above and below, next() here can't be
    // non-blocking: right after the burst there is no guarantee the
    // kernel has already posted every completion it owes us, and a 0ms
    // timeout racing that would just be a coin flip. Use a real timeout
    // and keep going until every write is accounted for.
    for (unsigned int i = 0;
         i < total_writes + 10 && total_reads < total_writes && !torn_read;
         ++i) {
        int result = 0;
        try {
            result = rawio::tests::run(
                *_queue, rawio::tests::wrap<int>(stream.next())
            );
        } catch (const std::system_error& e) {
            ASSERT_EQ(e.code().value(), ETIME);
            continue;
        }
        if (result != POLLIN) {
            continue;
        }
        char buf[total_writes];
        ssize_t n = ::read(read_fd, buf, sizeof(buf));
        if (n == -1) {
            // This is exactly the failure mode the fix prevents: being
            // told "readable" for a wakeup that a prior, same-batch
            // delivery already fully drained.
            torn_read = true;
            break;
        }
        total_reads += n;
    }

    EXPECT_FALSE(torn_read);
    EXPECT_EQ(total_reads, total_writes);

    _queue->cancel(event);
    EXPECT_NO_THROW(_wait_all());

    ::close(read_fd);
    ::close(write_fd);
}

TEST_F(MultishotTest, accept) {
    rawio::tests::Socket client_socket;
    rawio::tests::Socket server_socket1;
    rawio::tests::Socket server_socket2;

    client_socket.listen();

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    if (snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s",
            client_socket.name().data()
        ) < 0) {
        RAWSTD_THROW_ERRNO();
    }

    _server.connect(
        server_socket1.fd(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
    );
    _server.wait();

    rawio::AcceptStream stream = _queue->accept_multishot(client_socket.fd());

    int result =
        rawio::tests::run(*_queue, rawio::tests::wrap<int>(stream.next()));
    EXPECT_GT(result, 0);

    _server.connect(
        server_socket2.fd(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
    );
    _server.wait();

    result = rawio::tests::run(*_queue, rawio::tests::wrap<int>(stream.next()));
    EXPECT_GT(result, 0);

    rawio::Event* event = stream.event();
    EXPECT_NO_THROW(_queue->cancel(event));

    try {
        rawio::tests::run(*_queue, rawio::tests::wrap<int>(stream.next()));
        FAIL() << "expected ECANCELED";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

TEST_F(MultishotTest, recv) {
    const char server_buf[] = "dat1dat2";
    _server.write(server_buf, sizeof(server_buf) - 1);
    _server.wait();

    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 4, 4, 4, 0);

    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);

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

    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);

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

    rawio::Event* event = stream.event();
    EXPECT_NO_THROW(_queue->cancel(event));

    pull(*_queue, stream, 4, items);
    EXPECT_EQ(items.size(), (size_t)5);
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)0);
        EXPECT_EQ(items[4].error(), ECANCELED);
    }
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
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 8, 2, 4, 0);

    for (int i = 0; i < 5; ++i) {
        pull(*_queue, stream, 4, items);
    }

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

    EXPECT_THROW(_queue->cancel(stream.event()), std::system_error);
}

TEST_F(MultishotTest, recv_partial) {
    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 4, 4, 3, 0);

    {
        const char server_buf[] = "1234";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    pull(*_queue, stream, 3, items);
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

    pull(*_queue, stream, 3, items);
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

    pull(*_queue, stream, 3, items);
    pull(*_queue, stream, 3, items);
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

    rawio::Event* event = stream.event();
    EXPECT_NO_THROW(_queue->cancel(event));

    // The trailing data ("3") and the terminal ECANCELED arrive as two
    // separate pulls: the last byte on one next() and the terminal error
    // on the following one (see RecvStream::Next's doc comment).
    pull(*_queue, stream, 3, items);
    pull(*_queue, stream, 3, items);
    EXPECT_EQ(items.size(), (size_t)6);
    if (items.size() >= 5) {
        EXPECT_EQ(items[4].result(), (size_t)1);
        EXPECT_EQ(items[4].error(), 0);
        EXPECT_EQ(strncmp(items[4].data(), "3", 1), 0);
    }
    if (items.size() >= 6) {
        EXPECT_EQ(items[5].result(), (size_t)0);
        EXPECT_EQ(items[5].error(), ECANCELED);
    }
}

TEST_F(MultishotTest, recv_fill_buf) {
    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 4, 4, 4, 0);

    {
        const char server_buf[] = "123";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    // Nobody's pulling yet: in a pull model there is nothing to assert
    // here beyond "the registration accepts the data without anyone
    // consuming it" -- delivery only ever happens in response to a
    // next() call, so under-full data can never be delivered eagerly.
    EXPECT_NO_THROW(_wait_all());
    EXPECT_EQ(items.size(), (size_t)0);

    {
        const char server_buf[] = "456";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }
    EXPECT_NO_THROW(_wait_all());

    pull(*_queue, stream, 4, items);
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

    pull(*_queue, stream, 4, items);
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

    pull(*_queue, stream, 4, items);
    EXPECT_EQ(items.size(), (size_t)3);
    if (items.size() >= 3) {
        EXPECT_EQ(items[2].result(), (size_t)4);
        EXPECT_EQ(items[2].error(), 0);
        EXPECT_EQ(strncmp(items[2].data(), "9012", 3), 0);
    }

    rawio::Event* event = stream.event();
    EXPECT_NO_THROW(_queue->cancel(event));

    pull(*_queue, stream, 4, items);
    EXPECT_EQ(items.size(), (size_t)4);
    if (items.size() >= 4) {
        EXPECT_EQ(items[3].result(), (size_t)0);
        EXPECT_EQ(items[3].error(), ECANCELED);
    }
}

TEST_F(MultishotTest, stop_iteration) {
    {
        const char server_buf[] = "dat1dat2dat3";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 8, 4, 4, 0);

    pull(*_queue, stream, 4, items);
    EXPECT_EQ(items.size(), (size_t)1);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "dat1", 4), 0);
    }

    // Not calling next() again until more data is wanted is how the pull
    // model pauses a registration.
    rawio::Event* event = stream.event();
    EXPECT_NO_THROW(_queue->cancel(event));

    pull(*_queue, stream, 0, items);
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
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 8, 4, 4, 0);

    pull(*_queue, stream, 4, items);
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

    // Still "paused" (never asked for more than 0 again), but the kernel
    // ran the provided-buffer pool dry regardless -- that overflow must
    // still surface.
    pull(*_queue, stream, 0, items);
    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)0);
        EXPECT_EQ(items[1].error(), ENOBUFS);
    }

    EXPECT_THROW(_queue->cancel(stream.event()), std::system_error);
}

TEST_F(MultishotTest, recv_close_partial) {
    {
        const char server_buf[] = "dat1dat2dat";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.close();
        _server.wait();
    }

    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 8, 4, 4, 0);

    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);
    // The trailing "dat" and the terminal EPIPE arrive as two separate
    // pulls: the trailing data on one next() and the terminal error on
    // the following one (see RecvStream::Next's doc comment).
    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);

    EXPECT_EQ(items.size(), (size_t)4);
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
        EXPECT_EQ(items[2].result(), (size_t)3);
        EXPECT_EQ(items[2].error(), 0);
        EXPECT_EQ(strncmp(items[2].data(), "dat", 3), 0);
    }
    if (items.size() >= 4) {
        EXPECT_EQ(items[3].result(), (size_t)0);
        EXPECT_EQ(items[3].error(), EPIPE);
    }

    EXPECT_THROW(_queue->cancel(stream.event()), std::system_error);
}

TEST_F(MultishotTest, recv_close_full) {
    {
        const char server_buf[] = "dat1dat2dat3";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.close();
        _server.wait();
    }

    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 8, 4, 4, 0);

    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);
    pull(*_queue, stream, 4, items);

    EXPECT_EQ(items.size(), (size_t)4);
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
        EXPECT_EQ(items[3].result(), (size_t)0);
        EXPECT_EQ(items[3].error(), EPIPE);
    }

    EXPECT_THROW(_queue->cancel(stream.event()), std::system_error);
}

TEST_F(MultishotTest, recv_cancel_in_cb) {
    {
        const char server_buf[] = "dat1";
        _server.write(server_buf, sizeof(server_buf) - 1);
        _server.wait();
    }

    std::vector<MultishotVectorItem> items;
    rawio::RecvStream stream = _queue->recv_multishot(_fd, 8, 4, 4, 0);

    try {
        rawio::RecvStream::Item item = rawio::tests::run(
            *_queue, rawio::tests::wrap<rawio::RecvStream::Item>(stream.next(4))
        );
        EXPECT_NO_THROW(_queue->cancel(stream.event()));
        items.emplace_back(item.iov(), item.niov(), item.size(), 0);
    } catch (const std::system_error& e) {
        items.emplace_back(nullptr, 0, 0, e.code().value());
    }

    pull(*_queue, stream, 4, items);

    EXPECT_EQ(items.size(), (size_t)2);
    if (items.size() >= 1) {
        EXPECT_EQ(items[0].result(), (size_t)4);
        EXPECT_EQ(items[0].error(), 0);
        EXPECT_EQ(strncmp(items[0].data(), "dat1", 4), 0);
    }
    if (items.size() >= 2) {
        EXPECT_EQ(items[1].result(), (size_t)0);
        EXPECT_EQ(items[1].error(), ECANCELED);
    }

    EXPECT_THROW(_queue->cancel(stream.event()), std::system_error);
}

} // unnamed namespace
