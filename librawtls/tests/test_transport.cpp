#include <gtest/gtest.h>

#include <rawtls/context.hpp>
#include <rawtls/session.hpp>
#include <rawtls/transport.hpp>

#include "pki.hpp"

#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/socket.h>

#include <chrono>
#include <cstring>
#include <memory>
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
const std::string tenant = "0198f1a2-3b4c-7d5e-8f90-0123456789ab";

std::string server_uri() {
    return "spiffe://" + domain + "/ost/" + ost_id;
}

std::string client_uri() {
    return "spiffe://" + domain + "/tenant/" + tenant + "/client/vm42";
}

IssueOptions with_uri(const std::string& uri) {
    IssueOptions options;
    options.uris = {uri};
    return options;
}

rawtls::Config config(const Pki& pki, const Identity& identity) {
    rawtls::Config c;
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

rawstd::Task<size_t> send_all(Transport& t, const std::string& data) {
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
            *queue, pair.fds[0], client_context, rawtls::Session::Mode::client,
            server_uri()
        );
        rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
            *queue, pair.fds[1], server_context, rawtls::Session::Mode::server
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

TEST_F(TransportTest, HandshakeNamesThePeers) {
    std::unique_ptr<Transport> client, server;
    connect_tls(client, server);
    ASSERT_NE(client, nullptr);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(client->peer(), nullptr);
    ASSERT_NE(server->peer(), nullptr);
    EXPECT_EQ(client->peer()->role, rawtls::Role::ost);
    EXPECT_EQ(client->peer()->name, ost_id);
    EXPECT_EQ(server->peer()->role, rawtls::Role::client);
    EXPECT_EQ(server->peer()->tenant, tenant);
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

    rawstd::Task<void> cancel = [&]() -> rawstd::Task<void> {
        co_await server->cancel_receive(stream.event());
    }();
    ASSERT_TRUE(pump(*queue, [&]() { return read.done() && cancel.done(); }));
    cancel.get();
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
        *queue, pair.fds[0], client_context, rawtls::Session::Mode::client,
        server_uri()
    );
    rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
        *queue, pair.fds[1], server_context, rawtls::Session::Mode::server
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

TEST_F(TransportTest, PlainPeerFailsTheTlsHandshake) {
    rawtls::Context server_context(config(pki, server_identity));
    rawstd::Task<std::unique_ptr<Transport>> s = Transport::tls(
        *queue, pair.fds[1], server_context, rawtls::Session::Mode::server
    );
    const char junk[] = "GET / HTTP/1.1\r\n\r\n";
    ASSERT_EQ(write(pair.fds[0], junk, sizeof(junk)), (ssize_t)sizeof(junk));
    ASSERT_TRUE(pump(*queue, [&]() { return s.done(); }));
    EXPECT_THROW(s.get(), std::system_error);
}
