#include <gtest/gtest.h>

#include <rawtls/context.hpp>
#include <rawtls/transport.hpp>

#include "pki.hpp"

#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/socket.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <system_error>
#include <vector>

#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace {

using rawtls::Transport;
using rawtls::testing::Identity;
using rawtls::testing::IssueOptions;
using rawtls::testing::Pki;

const std::string domain = "cluster.example";
const std::string ost_id = "0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";
const std::string account = "0198f1a2-3b4c-7d5e-8f90-0123456789ab";

std::string server_uri() {
    return "spiffe://" + domain + "/ost/" + ost_id;
}

std::string client_uri() {
    return "spiffe://" + domain + "/account/" + account + "/client/vm42";
}

IssueOptions with_uri(const std::string& uri) {
    IssueOptions options;
    options.uris = {uri};
    return options;
}

rawtls::Config
config(const Pki& pki, const Identity& identity, const std::string& crl = "") {
    rawtls::Config c;
    c.crl_file = crl;
    c.trust_domain = domain;
    c.cert_file = identity.cert_file;
    c.key_file = identity.key_file;
    c.ca_file = pki.ca_file();
    return c;
}

// Drives the queue until `done()` or `msec` passes, and tells which.
template <typename Done>
bool pump(rawio::Queue& queue, Done done, unsigned int msec = 5000) {
    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(msec);
    while (!done() && std::chrono::steady_clock::now() < deadline) {
        try {
            queue.wait_timeout(10);
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
    return done();
}

// `data` is taken by value: it lives in the coroutine's frame until the send
// has completed, as a send's buffer must.
rawstd::Task<size_t> send_all(Transport& t, std::string data) {
    co_return co_await t.send(data.data(), data.size(), RAWSTD_MSG_NOSIGNAL);
}

rawstd::Task<size_t>
sendmsg_all(Transport& t, std::vector<std::string>& parts) {
    std::vector<iovec> iov;
    for (std::string& part : parts) {
        iov.push_back({part.data(), part.size()});
    }
    msghdr msg{};
    msg.msg_iov = iov.data();
    msg.msg_iovlen = iov.size();
    co_return co_await t.sendmsg(&msg, RAWSTD_MSG_NOSIGNAL);
}

rawstd::Task<void>
read_exact(rawio::RecvStream& stream, size_t size, std::string& out) {
    rawio::RecvStream::Item item = co_await stream.next(size);
    out.clear();
    for (unsigned int i = 0; i < item.niov(); ++i) {
        out.append(
            static_cast<const char*>(item.iov()[i].iov_base),
            item.iov()[i].iov_len
        );
    }
}

struct Pair {
    int fds[2] = {-1, -1};

    Pair() {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            throw std::system_error(errno, std::generic_category());
        }
        rawio::Queue::setup_fd(fds[0]);
        rawio::Queue::setup_fd(fds[1]);
    }

    ~Pair() {
        close(fds[0]);
        close(fds[1]);
    }
};

class TransportTest : public ::testing::Test {
protected:
    Pki pki;
    Identity server_identity;
    Identity client_identity;
    std::unique_ptr<rawio::Queue> queue;
    Pair pair;

    void SetUp() override {
        server_identity = pki.issue("server", with_uri(server_uri()));
        client_identity = pki.issue("client", with_uri(client_uri()));
        queue = rawio::Queue::create(32);
    }

    // The two ends of the pair, TLS-connected, the client end first.
    void connect_tls(
        std::unique_ptr<Transport>& client, std::unique_ptr<Transport>& server
    ) {
        rawtls::Context client_context(config(pki, client_identity));
        rawtls::Context server_context(config(pki, server_identity));
        rawstd::Task<std::unique_ptr<Transport>> c = Transport::tls(
            *queue, pair.fds[0], client_context, rawtls::Mode::client,
            server_uri()
        );
        rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
            *queue, pair.fds[1], server_context, rawtls::Mode::server
        );
        ASSERT_TRUE(pump(*queue, [&]() { return c.done() && s.done(); }));
        client = c.get();
        server = s.get();
    }
};

} // namespace

TEST_F(TransportTest, PlainCarriesBytesAsTheyAre) {
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);
    std::unique_ptr<Transport> b = Transport::plain(*queue, pair.fds[1]);
    EXPECT_EQ(a->peer(), nullptr);

    rawio::RecvStream stream = b->recv_multishot(4096, 8, 5, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 5, received);
    rawstd::Task<size_t> sent = send_all(*a, "hello");
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    EXPECT_EQ(sent.get(), 5u);
    read.get();
    EXPECT_EQ(received, "hello");
}

namespace {

// A socket buffer far smaller than what the tests send, so that a send of the
// socket comes up short.
void shrink_send_buffer(int fd) {
    int size = 4096;
    ASSERT_EQ(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)), 0);
}

// Reads `size` bytes from a plain stream a piece at a time: its ring holds a
// few entries, far fewer than a large payload.
rawstd::Task<void>
read_pieces(rawio::RecvStream& stream, size_t size, std::string& out) {
    out.clear();
    while (out.size() < size) {
        rawio::RecvStream::Item item =
            co_await stream.next(std::min<size_t>(size - out.size(), 4096));
        for (unsigned int i = 0; i < item.niov(); ++i) {
            out.append(
                static_cast<const char*>(item.iov()[i].iov_base),
                item.iov()[i].iov_len
            );
        }
    }
}

std::string random_bytes(size_t size, unsigned int seed) {
    std::string bytes(size, '\0');
    std::mt19937 gen(seed);
    for (char& c : bytes) {
        c = static_cast<char>(gen());
    }
    return bytes;
}

} // namespace

TEST_F(TransportTest, PlainSendmsgSendsAllOfALargePayload) {
    shrink_send_buffer(pair.fds[0]);
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);
    std::unique_ptr<Transport> b = Transport::plain(*queue, pair.fds[1]);

    std::vector<std::string> parts = {
        random_bytes(300 << 10, 1), "", random_bytes(1, 2),
        random_bytes(700 << 10, 3)
    };
    std::string expected = parts[0] + parts[1] + parts[2] + parts[3];
    std::vector<std::string> before = parts;

    rawio::RecvStream stream = b->recv_multishot(4096, 8, 0, 0);
    std::string received;
    rawstd::Task<void> read = read_pieces(stream, expected.size(), received);
    rawstd::Task<size_t> sent = sendmsg_all(*a, parts);
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    EXPECT_EQ(sent.get(), expected.size());
    read.get();
    EXPECT_TRUE(received == expected);
    EXPECT_EQ(parts, before);
}

TEST_F(TransportTest, PlainSendSendsAllOfALargePayload) {
    shrink_send_buffer(pair.fds[0]);
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);
    std::unique_ptr<Transport> b = Transport::plain(*queue, pair.fds[1]);

    std::string payload = random_bytes(1 << 20, 4);
    rawio::RecvStream stream = b->recv_multishot(4096, 8, 0, 0);
    std::string received;
    rawstd::Task<void> read = read_pieces(stream, payload.size(), received);
    rawstd::Task<size_t> sent = send_all(*a, payload);
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    EXPECT_EQ(sent.get(), payload.size());
    read.get();
    EXPECT_TRUE(received == payload);
}

TEST_F(TransportTest, PlainConcurrentSendsAreNotInterleaved) {
    shrink_send_buffer(pair.fds[0]);
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);
    std::unique_ptr<Transport> b = Transport::plain(*queue, pair.fds[1]);

    std::string one(1 << 20, 'a');
    std::string two(1 << 20, 'b');
    std::string three(1 << 20, 'c');
    rawio::RecvStream stream = b->recv_multishot(4096, 8, 0, 0);
    std::string received;
    rawstd::Task<void> read =
        read_pieces(stream, one.size() + two.size() + three.size(), received);
    rawstd::Task<size_t> sent_one = send_all(*a, one);
    rawstd::Task<size_t> sent_two = send_all(*a, two);
    rawstd::Task<size_t> sent_three = send_all(*a, three);
    ASSERT_TRUE(pump(*queue, [&]() {
        return read.done() && sent_one.done() && sent_two.done() &&
               sent_three.done();
    }));
    sent_one.get();
    sent_two.get();
    sent_three.get();
    read.get();
    EXPECT_TRUE(received == one + two + three);
}

TEST_F(TransportTest, PlainShortSendmsgPassesAncillaryDataOnce) {
    shrink_send_buffer(pair.fds[0]);
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);

    int pipe_fds[2];
    ASSERT_EQ(pipe(pipe_fds), 0);
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        cmsghdr align;
    } control{};
    std::string payload = random_bytes(1 << 20, 5);
    iovec iov{payload.data(), payload.size()};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);
    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pipe_fds[0], sizeof(int));

    // The peer is read directly, to see the descriptors that arrive.
    std::vector<char> buf(1 << 16);
    size_t received = 0;
    unsigned int descriptors = 0;
    rawstd::Task<size_t> sent = a->sendmsg(&msg, RAWSTD_MSG_NOSIGNAL);
    ASSERT_TRUE(pump(*queue, [&]() {
        for (;;) {
            union {
                char buf[CMSG_SPACE(16 * sizeof(int))];
                cmsghdr align;
            } in{};
            iovec in_iov{buf.data(), buf.size()};
            msghdr in_msg{};
            in_msg.msg_iov = &in_iov;
            in_msg.msg_iovlen = 1;
            in_msg.msg_control = in.buf;
            in_msg.msg_controllen = sizeof(in.buf);
            ssize_t n = recvmsg(pair.fds[1], &in_msg, MSG_DONTWAIT);
            if (n <= 0) {
                break;
            }
            received += static_cast<size_t>(n);
            for (cmsghdr* c = CMSG_FIRSTHDR(&in_msg); c != nullptr;
                 c = CMSG_NXTHDR(&in_msg, c)) {
                if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
                    size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                    for (size_t i = 0; i < count; ++i) {
                        int fd;
                        memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(fd));
                        close(fd);
                        ++descriptors;
                    }
                }
            }
        }
        return sent.done() && received == payload.size();
    }));
    EXPECT_EQ(sent.get(), payload.size());
    EXPECT_EQ(descriptors, 1u);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

TEST_F(TransportTest, PlainSendFailingMidwayBreaksTheConnection) {
    shrink_send_buffer(pair.fds[0]);
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);

    // Nobody reads: the first send goes out in part and waits for room.
    rawstd::Task<size_t> first = send_all(*a, std::string(1 << 20, 'a'));
    pump(*queue, [&]() { return first.done(); }, 100);
    ASSERT_FALSE(first.done());

    // The peer ends the connection; the send fails with a frame half sent.
    ASSERT_EQ(shutdown(pair.fds[1], SHUT_RDWR), 0);
    ASSERT_TRUE(pump(*queue, [&]() { return first.done(); }));
    EXPECT_THROW(first.get(), std::system_error);

    rawstd::Task<size_t> next = send_all(*a, "b");
    ASSERT_TRUE(pump(*queue, [&]() { return next.done(); }));
    try {
        next.get();
        FAIL() << "a send after a half-sent frame must fail";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECONNABORTED);
    }
}

TEST_F(TransportTest, HandshakeNamesThePeers) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);
    ASSERT_NE(client, nullptr);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(client->peer(), nullptr);
    ASSERT_NE(server->peer(), nullptr);
    EXPECT_EQ(client->peer()->type(), rawtls::Type::ost);
    EXPECT_EQ(client->peer()->name(), ost_id);
    EXPECT_EQ(server->peer()->type(), rawtls::Type::client);
    EXPECT_EQ(server->peer()->account(), account);
}

TEST_F(TransportTest, BytesGoBothWaysThroughTls) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    rawio::RecvStream from_client = server->recv_multishot(4096, 8, 5, 0);
    rawio::RecvStream from_server = client->recv_multishot(4096, 8, 6, 0);
    std::string at_server, at_client;
    rawstd::Task<void> read_s = read_exact(from_client, 5, at_server);
    rawstd::Task<void> read_c = read_exact(from_server, 6, at_client);
    rawstd::Task<size_t> sent_c = send_all(*client, "hello");
    rawstd::Task<size_t> sent_s = send_all(*server, "world!");
    ASSERT_TRUE(pump(*queue, [&]() {
        return read_s.done() && read_c.done() && sent_c.done() && sent_s.done();
    }));
    EXPECT_EQ(sent_c.get(), 5u);
    EXPECT_EQ(sent_s.get(), 6u);
    read_s.get();
    read_c.get();
    EXPECT_EQ(at_server, "hello");
    EXPECT_EQ(at_client, "world!");
}

TEST_F(TransportTest, SendmsgGathersTheVectors) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    std::vector<std::string> parts = {"abc", "", "defg", "h"};
    rawio::RecvStream stream = server->recv_multishot(4096, 8, 8, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 8, received);
    rawstd::Task<size_t> sent = sendmsg_all(*client, parts);
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    EXPECT_EQ(sent.get(), 8u);
    read.get();
    EXPECT_EQ(received, "abcdefgh");
}

TEST_F(TransportTest, LargePayloadArrivesWhole) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    std::string payload(3 << 20, '\0');
    std::mt19937 gen(7);
    for (char& c : payload) {
        c = static_cast<char>(gen());
    }
    rawio::RecvStream stream = server->recv_multishot(4096, 8, 0, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, payload.size(), received);
    rawstd::Task<size_t> sent = send_all(*client, payload);
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    EXPECT_EQ(sent.get(), payload.size());
    read.get();
    EXPECT_TRUE(received == payload);
}

TEST_F(TransportTest, ConcurrentSendsAreNotInterleaved) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    std::string a(1 << 20, 'a');
    std::string b(1 << 20, 'b');
    rawio::RecvStream stream = server->recv_multishot(4096, 8, 0, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, a.size() + b.size(), received);
    rawstd::Task<size_t> sent_a = send_all(*client, a);
    rawstd::Task<size_t> sent_b = send_all(*client, b);
    ASSERT_TRUE(pump(*queue, [&]() {
        return read.done() && sent_a.done() && sent_b.done();
    }));
    sent_a.get();
    sent_b.get();
    read.get();
    EXPECT_TRUE(received == a + b);
}

TEST_F(TransportTest, FramesInOneStreamKeepTheirBoundaries) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    // Reads of the sizes a frame head and its body would ask for.
    rawio::RecvStream stream = server->recv_multishot(4096, 8, 0, 0);
    std::string data;
    for (int i = 0; i < 100; ++i) {
        data += std::string(i + 1, static_cast<char>('A' + i % 26));
    }
    rawstd::Task<size_t> sent = send_all(*client, data);
    std::string received;
    for (int i = 0; i < 100; ++i) {
        std::string part;
        rawstd::Task<void> read = read_exact(stream, i + 1, part);
        ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
        read.get();
        received += part;
        EXPECT_EQ(part, std::string(i + 1, static_cast<char>('A' + i % 26)));
    }
    ASSERT_TRUE(pump(*queue, [&]() { return sent.done(); }));
    EXPECT_EQ(received, data);
}

TEST_F(TransportTest, PeerClosingEndsTheStream) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    rawio::RecvStream stream = server->recv_multishot(4096, 8, 4, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 4, received);
    shutdown(pair.fds[0], SHUT_WR);
    ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
    try {
        read.get();
        FAIL() << "read succeeded after the peer closed";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EPIPE);
    }
}

TEST_F(TransportTest, CancelReceiveFailsThePendingRead) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    rawio::RecvStream stream = server->recv_multishot(4096, 8, 4, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 4, received);
    EXPECT_FALSE(pump(*queue, [&]() { return read.done(); }, 50));

    server->cancel_recv_multishot();
    ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
    try {
        read.get();
        FAIL() << "the read was not cancelled";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

// A stream started while its predecessor is still alive, as when the receive
// ring of a connection is replaced, is not stopped when the old one goes.
TEST_F(TransportTest, DestroyingAnOldStreamDoesNotStopTheNewOne) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    std::unique_ptr<rawio::RecvStream> old_stream =
        std::make_unique<rawio::RecvStream>(
            server->recv_multishot(4096, 8, 4, 0)
        );
    std::string old_received;
    rawstd::Task<void> old_read = read_exact(*old_stream, 4, old_received);
    EXPECT_FALSE(pump(*queue, [&]() { return old_read.done(); }, 50));
    server->cancel_recv_multishot();
    ASSERT_TRUE(pump(*queue, [&]() { return old_read.done(); }));
    EXPECT_THROW(old_read.get(), std::system_error);

    rawio::RecvStream stream = server->recv_multishot(4096, 8, 4, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 4, received);
    EXPECT_FALSE(pump(*queue, [&]() { return read.done(); }, 50));

    old_stream.reset();

    rawstd::Task<size_t> sent = send_all(*client, "ping");
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    read.get();
    EXPECT_EQ(received, "ping");
}

// A stream does not wait for data of a connection that is gone.
TEST_F(TransportTest, DestroyingTheTransportEndsItsStream) {
    std::unique_ptr<Transport> plain = Transport::plain(*queue, pair.fds[1]);
    rawio::RecvStream stream = plain->recv_multishot(4096, 8, 4, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 4, received);
    EXPECT_FALSE(pump(*queue, [&]() { return read.done(); }, 50));

    plain.reset();
    ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
    try {
        read.get();
        FAIL() << "the read was not cancelled";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

TEST_F(TransportTest, DestroyingTheTlsTransportEndsItsStream) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);
    rawio::RecvStream stream = server->recv_multishot(4096, 8, 4, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 4, received);
    EXPECT_FALSE(pump(*queue, [&]() { return read.done(); }, 50));

    server.reset();
    ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
    try {
        read.get();
        FAIL() << "the read was not cancelled";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ECANCELED);
    }
}

TEST_F(TransportTest, StreamCanBeStartedAgainAfterCancel) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);

    {
        rawio::RecvStream stream = server->recv_multishot(4096, 8, 4, 0);
        std::string ignored;
        rawstd::Task<void> read = read_exact(stream, 4, ignored);
        stream.close();
        ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
        EXPECT_THROW(read.get(), std::system_error);
    }

    rawio::RecvStream stream = server->recv_multishot(4096, 8, 4, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 4, received);
    rawstd::Task<size_t> sent = send_all(*client, "ping");
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    read.get();
    EXPECT_EQ(received, "ping");
}

TEST_F(TransportTest, RefusedServerFailsTheClientHandshake) {
    Identity impostor = pki.issue(
        "impostor", with_uri(
                        "spiffe://" + domain + "/ost/" +
                        std::string("0198f1a2-3b4c-7d5e-8f90-ffffffffffff")
                    )
    );
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, impostor));
    rawstd::Task<std::unique_ptr<Transport>> c = Transport::tls(
        *queue, pair.fds[0], client_context, rawtls::Mode::client, server_uri()
    );
    rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
        *queue, pair.fds[1], server_context, rawtls::Mode::server
    );
    ASSERT_TRUE(pump(*queue, [&]() { return c.done() && s.done(); }));
    try {
        c.get();
        FAIL() << "the client accepted the wrong server";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EACCES);
    }
    EXPECT_THROW(s.get(), std::system_error);
}

TEST_F(TransportTest, SilentPeerTimesTheHandshakeOut) {
    rawtls::Context server_context(config(pki, server_identity));
    rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
        *queue, pair.fds[1], server_context, rawtls::Mode::server, "",
        std::nullopt, 100
    );
    EXPECT_FALSE(pump(*queue, [&]() { return s.done(); }, 30));
    ASSERT_TRUE(pump(*queue, [&]() { return s.done(); }));
    try {
        s.get();
        FAIL() << "the handshake completed without a peer";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ETIMEDOUT);
    }
}

TEST_F(TransportTest, PlainPeerFailsTheTlsHandshake) {
    rawtls::Context server_context(config(pki, server_identity));
    rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
        *queue, pair.fds[1], server_context, rawtls::Mode::server
    );
    const char junk[] = "GET / HTTP/1.1\r\n\r\n";
    ASSERT_EQ(write(pair.fds[0], junk, sizeof(junk)), (ssize_t)sizeof(junk));
    ASSERT_TRUE(pump(*queue, [&]() { return s.done(); }));
    EXPECT_THROW(s.get(), std::system_error);
}

namespace {

const std::string ost_b = "0198f1a2-3b4c-7d5e-8f90-b1b2c3d4e5f6";

std::string ost_uri(const std::string& id) {
    return "spiffe://" + domain + "/ost/" + id;
}

// The two ends of a handshake: the Transport each one ended with (null for an
// end that failed) and the error it failed with (0 for none).
struct Opened {
    std::unique_ptr<Transport> client;
    std::unique_ptr<Transport> server;
    int client_error = 0;
    int server_error = 0;
};

int finish(
    rawstd::Task<std::unique_ptr<Transport>>& task,
    std::unique_ptr<Transport>& out
) {
    try {
        out = task.get();
    } catch (const std::system_error& e) {
        return e.code().value();
    }
    return 0;
}

class HandshakeTest : public TransportTest {
protected:
    // Opens the two ends of `fds`, a client that expects `expected` (or a
    // server of `type`) against a server.
    Opened open_both(
        Pair& fds, rawtls::Context& client_context,
        rawtls::Context& server_context, const std::string& expected,
        std::optional<rawtls::Type> type = std::nullopt
    ) {
        Opened result;
        rawstd::Task<std::unique_ptr<Transport>> c = Transport::tls(
            *queue, fds.fds[0], client_context, rawtls::Mode::client, expected,
            type
        );
        rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
            *queue, fds.fds[1], server_context, rawtls::Mode::server
        );
        EXPECT_TRUE(pump(*queue, [&]() { return c.done() && s.done(); }));
        result.client_error = finish(c, result.client);
        result.server_error = finish(s, result.server);
        return result;
    }

    // A handshake between a client holding `client_id` that expects
    // `expected` and a server holding `server_id`.
    Opened
    run(const std::string& expected, const Identity& client_id,
        const Identity& server_id, const std::string& crl = "") {
        rawtls::Context client_context(config(pki, client_id, crl));
        rawtls::Context server_context(config(pki, server_id));
        return open_both(pair, client_context, server_context, expected);
    }

    void replace_server_identity(const Identity& renewed) {
        std::filesystem::copy_file(
            renewed.cert_file, server_identity.cert_file,
            std::filesystem::copy_options::overwrite_existing
        );
        std::filesystem::copy_file(
            renewed.key_file, server_identity.key_file,
            std::filesystem::copy_options::overwrite_existing
        );
    }
};

} // namespace

TEST_F(HandshakeTest, WrongServerIdentityIsRefused) {
    Opened r = run(ost_uri(ost_b), client_identity, server_identity);
    EXPECT_EQ(r.client_error, EACCES);
}

TEST_F(HandshakeTest, ServerInAnotherTrustDomainIsRefused) {
    Identity other = pki.issue(
        "other-domain", with_uri("spiffe://other.example/ost/" + ost_id)
    );
    Opened r = run(server_uri(), client_identity, other);
    EXPECT_EQ(r.client_error, EACCES);
}

TEST_F(HandshakeTest, ClientInAnotherTrustDomainIsRefused) {
    Identity other = pki.issue(
        "other-client",
        with_uri("spiffe://other.example/account/" + account + "/client/vm42")
    );
    Opened r = run(server_uri(), other, server_identity);
    EXPECT_EQ(r.server_error, EACCES);
}

TEST_F(HandshakeTest, ServerWithAClientIdentityIsRefused) {
    Identity impostor = pki.issue("impostor", with_uri(client_uri()));
    Opened r = run(server_uri(), client_identity, impostor);
    EXPECT_EQ(r.client_error, EACCES);
}

TEST_F(HandshakeTest, CertificateOfAnotherCaIsRefused) {
    Pki foreign;
    Identity foreign_server =
        foreign.issue("foreign-server", with_uri(server_uri()));
    Identity foreign_client =
        foreign.issue("foreign-client", with_uri(client_uri()));

    EXPECT_EQ(
        run(server_uri(), client_identity, foreign_server).client_error, EACCES
    );
    Pair second;
    rawtls::Context client_context(config(pki, foreign_client));
    rawtls::Context server_context(config(pki, server_identity));
    EXPECT_EQ(
        open_both(second, client_context, server_context, server_uri())
            .server_error,
        EACCES
    );
}

TEST_F(HandshakeTest, ExpiredCertificateIsRefused) {
    IssueOptions options = with_uri(server_uri());
    options.not_before = -7200;
    options.not_after = -3600;
    Identity expired = pki.issue("expired", options);
    EXPECT_EQ(run(server_uri(), client_identity, expired).client_error, EACCES);
}

TEST_F(HandshakeTest, CertificateNotYetValidIsRefused) {
    IssueOptions options = with_uri(server_uri());
    options.not_before = 3600;
    options.not_after = 7200;
    Identity early = pki.issue("early", options);
    EXPECT_EQ(run(server_uri(), client_identity, early).client_error, EACCES);
}

TEST_F(HandshakeTest, NoUriSanIsRefused) {
    Identity bare = pki.issue("bare", IssueOptions());
    EXPECT_EQ(run(server_uri(), client_identity, bare).client_error, EACCES);
}

TEST_F(HandshakeTest, SeveralUriSansAreRefused) {
    IssueOptions options;
    options.uris = {server_uri(), ost_uri(ost_b)};
    Identity two = pki.issue("two", options);
    EXPECT_EQ(run(server_uri(), client_identity, two).client_error, EACCES);
}

TEST_F(HandshakeTest, UriSanThatIsNotAnIdIsRefused) {
    Identity web = pki.issue("web", with_uri("https://example.com/ost"));
    EXPECT_EQ(run(server_uri(), client_identity, web).client_error, EACCES);
}

TEST_F(HandshakeTest, MissingExtendedKeyUsageIsRefused) {
    IssueOptions options = with_uri(server_uri());
    options.usage = false;
    Identity unrestricted = pki.issue("unrestricted", options);
    EXPECT_EQ(
        run(server_uri(), client_identity, unrestricted).client_error, EACCES
    );
}

TEST_F(HandshakeTest, ExtendedKeyUsageOfTheOtherEndIsRefused) {
    IssueOptions as_client = with_uri(server_uri());
    as_client.server_auth = false;
    Identity client_only = pki.issue("client-only", as_client);
    EXPECT_EQ(
        run(server_uri(), client_identity, client_only).client_error, EACCES
    );

    Pair second;
    IssueOptions as_server = with_uri(client_uri());
    as_server.client_auth = false;
    Identity server_only = pki.issue("server-only", as_server);
    rawtls::Context client_context(config(pki, server_only));
    rawtls::Context server_context(config(pki, server_identity));
    EXPECT_EQ(
        open_both(second, client_context, server_context, server_uri())
            .server_error,
        EACCES
    );
}

TEST_F(HandshakeTest, CaCertificateAsALeafIsRefused) {
    IssueOptions options = with_uri(server_uri());
    options.ca = true;
    Identity ca_leaf = pki.issue("ca-leaf", options);
    EXPECT_EQ(run(server_uri(), client_identity, ca_leaf).client_error, EACCES);
}

TEST_F(HandshakeTest, RefusedClientLearnsOnTheNextRead) {
    Identity other = pki.issue(
        "other-client",
        with_uri("spiffe://other.example/account/" + account + "/client/vm42")
    );
    Opened r = run(server_uri(), other, server_identity);
    EXPECT_EQ(r.server_error, EACCES);
    ASSERT_NE(r.client, nullptr);

    rawio::RecvStream stream = r.client->recv_multishot(4096, 8, 1, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 1, received);
    ASSERT_TRUE(pump(*queue, [&]() { return read.done(); }));
    try {
        read.get();
        FAIL() << "the alert did not arrive";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EPROTO);
    }
}

TEST_F(HandshakeTest, RevokedCertificateIsRefused) {
    std::string crl = pki.crl({server_identity.serial});
    EXPECT_EQ(
        run(server_uri(), client_identity, server_identity, crl).client_error,
        EACCES
    );
}

TEST_F(HandshakeTest, CertificateNotOnTheCrlIsAccepted) {
    std::string crl = pki.crl({server_identity.serial + 100});
    Opened r = run(server_uri(), client_identity, server_identity, crl);
    EXPECT_EQ(r.client_error, 0);
    EXPECT_EQ(r.server_error, 0);
}

TEST_F(HandshakeTest, TlsOneTwoIsRefused) {
    rawtls::Context server_context(config(pki, server_identity));
    rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
        *queue, pair.fds[1], server_context, rawtls::Mode::server
    );

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    ASSERT_NE(ctx, nullptr);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL* ssl = SSL_new(ctx);
    BIO* rbio = BIO_new(BIO_s_mem());
    BIO* wbio = BIO_new(BIO_s_mem());
    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_connect_state(ssl);
    SSL_do_handshake(ssl);

    std::vector<char> hello(BIO_ctrl_pending(wbio));
    ASSERT_GT(BIO_read(wbio, hello.data(), static_cast<int>(hello.size())), 0);
    ASSERT_EQ(
        write(pair.fds[0], hello.data(), hello.size()),
        static_cast<ssize_t>(hello.size())
    );
    ASSERT_TRUE(pump(*queue, [&]() { return s.done(); }));
    try {
        s.get();
        FAIL() << "a TLS 1.2 client was accepted";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EPROTO);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

TEST_F(HandshakeTest, ReloadServesNewConnectionsWithTheNewCertificate) {
    Identity renewed = pki.issue("renewed", with_uri(ost_uri(ost_b)));
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));

    Opened first =
        open_both(pair, client_context, server_context, server_uri());
    ASSERT_NE(first.client, nullptr);
    ASSERT_NE(first.server, nullptr);

    replace_server_identity(renewed);
    server_context.request_reload();
    // A new connection is what applies it.
    server_context.snapshot();

    // An established connection keeps going over a reload.
    rawio::RecvStream stream = first.server->recv_multishot(4096, 8, 10, 0);
    std::string received;
    rawstd::Task<void> read = read_exact(stream, 10, received);
    rawstd::Task<size_t> sent = send_all(*first.client, "still here");
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && sent.done(); }));
    read.get();
    EXPECT_EQ(received, "still here");

    Pair second;
    EXPECT_EQ(
        open_both(second, client_context, server_context, server_uri())
            .client_error,
        EACCES
    );

    Pair third;
    Opened renewed_pair =
        open_both(third, client_context, server_context, ost_uri(ost_b));
    EXPECT_EQ(renewed_pair.client_error, 0);
    EXPECT_EQ(renewed_pair.server_error, 0);
}

TEST_F(HandshakeTest, RequestedReloadAppliesToTheNextConnection) {
    Identity renewed = pki.issue("renewed", with_uri(ost_uri(ost_b)));
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));

    replace_server_identity(renewed);
    server_context.request_reload();

    Opened r = open_both(pair, client_context, server_context, ost_uri(ost_b));
    EXPECT_EQ(r.client_error, 0);
    EXPECT_EQ(r.server_error, 0);
}

TEST_F(HandshakeTest, RequestedReloadOfBrokenFilesKeepsTheContext) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));

    {
        std::ofstream broken(server_identity.key_file, std::ios::trunc);
        broken << "not a key\n";
    }
    server_context.request_reload();

    Opened r = open_both(pair, client_context, server_context, server_uri());
    EXPECT_EQ(r.client_error, 0);
    EXPECT_EQ(r.server_error, 0);
}

TEST_F(HandshakeTest, ContextRejectsBrokenFiles) {
    rawtls::Config good = config(pki, server_identity);

    rawtls::Config missing_cert = good;
    missing_cert.cert_file = (pki.dir() / "nope.crt").string();
    EXPECT_THROW(rawtls::Context{missing_cert}, std::system_error);

    rawtls::Config missing_ca = good;
    missing_ca.ca_file = (pki.dir() / "nope.ca").string();
    EXPECT_THROW(rawtls::Context{missing_ca}, std::system_error);

    rawtls::Config mismatched = good;
    mismatched.key_file = client_identity.key_file;
    EXPECT_THROW(rawtls::Context{mismatched}, std::system_error);

    rawtls::Config missing_crl = good;
    missing_crl.crl_file = (pki.dir() / "nope.crl").string();
    EXPECT_THROW(rawtls::Context{missing_crl}, std::system_error);
}

TEST_F(HandshakeTest, ClientNeedsAnExpectedServerIdentity) {
    rawtls::Context context(config(pki, client_identity));
    EXPECT_THROW(
        Transport::tls(*queue, pair.fds[0], context, rawtls::Mode::client)
            .get(),
        std::system_error
    );
    EXPECT_THROW(
        Transport::tls(
            *queue, pair.fds[0], context, rawtls::Mode::client, "nonsense"
        )
            .get(),
        std::system_error
    );
    // The server it expects must be an OST or an MDS.
    EXPECT_THROW(
        Transport::tls(
            *queue, pair.fds[0], context, rawtls::Mode::client, client_uri()
        )
            .get(),
        std::system_error
    );
}

TEST_F(HandshakeTest, ClientMayExpectOnlyTheTypeOfTheServer) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));
    {
        Opened r = open_both(
            pair, client_context, server_context, "", rawtls::Type::ost
        );
        EXPECT_EQ(r.client_error, 0);
        ASSERT_NE(r.client, nullptr);
        EXPECT_EQ(r.client->peer()->name(), ost_id);
    }
    {
        Pair second;
        Opened r = open_both(
            second, client_context, server_context, "", rawtls::Type::mds
        );
        EXPECT_EQ(r.client_error, EACCES);
    }
    // Only the types of a server can be expected of one.
    EXPECT_THROW(
        Transport::tls(
            *queue, pair.fds[0], client_context, rawtls::Mode::client, "",
            rawtls::Type::admin
        )
            .get(),
        std::system_error
    );
}

namespace {

// Starts `count` sends of different sizes at once, so that the Transport has
// them all queued when it writes, and checks that each completes with its own
// size and that the peer gets their bytes whole and in the order started.
void check_concurrent_sends(
    rawio::Queue& queue, Transport& a, Transport& b, size_t count, size_t base
) {
    std::vector<std::string> payloads;
    std::string expected;
    for (size_t i = 0; i < count; ++i) {
        payloads.push_back(random_bytes(
            base + (i * 977) % (base + 1), static_cast<unsigned>(i)
        ));
        expected += payloads.back();
    }

    rawio::RecvStream stream = b.recv_multishot(4096, 64, 0, 0);
    std::string received;
    rawstd::Task<void> read = read_pieces(stream, expected.size(), received);
    // sendmsg_all() keeps a reference to its parts until the send is done.
    std::vector<std::vector<std::string>> parts(count);
    std::vector<rawstd::Task<size_t>> sends;
    for (size_t i = 0; i < count; ++i) {
        // Alternate the two calls: both go through the same queue.
        if (i % 2 == 0) {
            sends.push_back(send_all(a, payloads[i]));
        } else {
            parts[i] = {payloads[i].substr(0, 3), payloads[i].substr(3)};
            sends.push_back(sendmsg_all(a, parts[i]));
        }
    }
    ASSERT_TRUE(pump(queue, [&]() {
        if (!read.done()) {
            return false;
        }
        for (rawstd::Task<size_t>& send : sends) {
            if (!send.done()) {
                return false;
            }
        }
        return true;
    }));
    for (size_t i = 0; i < count; ++i) {
        EXPECT_EQ(sends[i].get(), payloads[i].size());
    }
    read.get();
    EXPECT_TRUE(received == expected);
}

} // namespace

TEST_F(TransportTest, PlainSendsStartedTogetherArriveWholeAndInOrder) {
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);
    std::unique_ptr<Transport> b = Transport::plain(*queue, pair.fds[1]);
    check_concurrent_sends(*queue, *a, *b, 200, 100);
}

TEST_F(TransportTest, PlainBatchOfSendsSurvivesShortSends) {
    shrink_send_buffer(pair.fds[0]);
    std::unique_ptr<Transport> a = Transport::plain(*queue, pair.fds[0]);
    std::unique_ptr<Transport> b = Transport::plain(*queue, pair.fds[1]);
    check_concurrent_sends(*queue, *a, *b, 64, 20000);
}

TEST_F(TransportTest, TlsSendsStartedTogetherArriveWholeAndInOrder) {
    std::unique_ptr<Transport> a;
    std::unique_ptr<Transport> b;
    connect_tls(a, b);
    ASSERT_TRUE(a && b);
    check_concurrent_sends(*queue, *a, *b, 200, 100);
}

TEST_F(TransportTest, TlsBatchOfSendsMixesSmallAndLargeBuffers) {
    std::unique_ptr<Transport> a;
    std::unique_ptr<Transport> b;
    connect_tls(a, b);
    ASSERT_TRUE(a && b);
    check_concurrent_sends(*queue, *a, *b, 40, 40000);
}
