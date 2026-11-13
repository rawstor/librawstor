#include "rawio_sync.hpp"
#include "tls_process.hpp"
#include "tmp_dir.hpp"

#include <pki.hpp>

#include <ost/server.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/pipe.hpp>

#include <rawstor/location.h>
#include <rawstor/rawstor.h>

#include <rawtls/context.hpp>
#include <rawtls/session.hpp>
#include <rawtls/transport.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <filesystem>
#include <future>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

using rawtls::testing::Identity;
using rawtls::testing::IssueOptions;
using rawtls::testing::Pki;

const std::string& domain = rawstor::tests::TlsProcess::trust_domain;
const std::string ost_id = "018f4e2a-0000-7000-8000-0000000000aa";
const std::string other_ost_id = "018f4e2a-0000-7000-8000-0000000000bb";

std::string ost_uri(const std::string& id) {
    return "spiffe://" + domain + "/ost/" + id;
}

// A real rawstor-ost on its own thread, serving a file:// directory.
class OstServer {
private:
    rawstor::tests::TmpDir _dir;
    int _listen_fd;
    int _wake_write_fd;
    std::thread _thread;
    unsigned int _port;

public:
    explicit OstServer(unsigned int port) :
        _listen_fd(rawstor::ostserver::Server::bind_listen("127.0.0.1", port)),
        _wake_write_fd(-1),
        _port(port) {
        rawstd::Pipe wake(rawstd::Pipe::Mode::NonBlocking);
        _wake_write_fd = wake.release_write();
        int wake_read_fd = wake.release_read();

        auto ready = std::make_shared<std::promise<void>>();
        std::future<void> ready_future = ready->get_future();
        std::string location = _dir.uri();
        _thread =
            std::thread([fd = _listen_fd, location, wake_read_fd, ready]() {
                try {
                    rawstor::ostserver::Server s(
                        64, fd, location.c_str(), wake_read_fd
                    );
                    ready->set_value();
                    s.loop();
                } catch (...) {
                    std::exception_ptr e = std::current_exception();
                    try {
                        ready->set_exception(e);
                    } catch (const std::future_error&) {
                    }
                }
            });
        ready_future.get();
    }

    OstServer(const OstServer&) = delete;
    OstServer& operator=(const OstServer&) = delete;

    ~OstServer() {
        char byte = 0;
        ssize_t ignored = write(_wake_write_fd, &byte, 1);
        (void)ignored;
        _thread.join();
        close(_wake_write_fd);
        close(_listen_fd);
    }

    std::string location() const {
        std::ostringstream oss;
        oss << "ost://127.0.0.1:" << _port;
        return oss.str();
    }

    // A TCP connection to the server, not yet speaking anything.
    int connect_raw() const {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(static_cast<uint16_t>(_port));
        inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
        if (connect(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) != 0) {
            close(fd);
            RAWSTD_THROW_ERRNO();
        }
        return fd;
    }
};

ssize_t location_info(
    rawio::Queue& queue, const std::string& location, RawstorLocationInfo* info
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_info(&queue, location.c_str(), info, cb, data);
    });
}

// Runs the TLS client handshake over `fd` with the identity files of
// `client_pki`'s `identity`, trusting `trust_pki`, and returns the error it
// ended with (0 for none).
int raw_handshake(
    int fd, const Pki& trust_pki, const Identity& identity,
    const std::string& expected_peer
) {
    rawtls::Config config;
    config.trust_domain = domain;
    config.cert_file = identity.cert_file;
    config.key_file = identity.key_file;
    config.ca_file = trust_pki.ca_file();
    rawtls::Context context(config);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    rawio::Queue::setup_fd(fd);
    rawstd::Task<std::unique_ptr<rawtls::Transport>> task =
        rawtls::Transport::tls(
            *queue, fd, context, rawtls::Session::Mode::client, expected_peer,
            rawtls::Role::ost, 5000
        );
    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!task.done() && std::chrono::steady_clock::now() < deadline) {
        try {
            queue->wait_timeout(10);
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
    EXPECT_TRUE(task.done());
    try {
        std::unique_ptr<rawtls::Transport> transport = task.get();
        return 0;
    } catch (const std::system_error& e) {
        return e.code().value();
    }
}

} // namespace

TEST(TlsTest, location_info_over_tls) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8900);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), 0);
    EXPECT_GT(info.total, (uint64_t)0);
}

TEST(TlsTest, a_silent_connection_does_not_hold_up_others) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8901);
    int silent = server.connect_raw();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), 0);
    EXPECT_GT(info.total, (uint64_t)0);

    close(silent);
}

TEST(TlsTest, a_plaintext_client_is_dropped) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8902);

    int fd = server.connect_raw();
    const char request[] = "GET / HTTP/1.0\r\n\r\n";
    ASSERT_EQ(
        send(fd, request, sizeof(request), MSG_NOSIGNAL),
        (ssize_t)sizeof(request)
    );
    // The server answers with an alert at most and closes the connection.
    pollfd p{fd, POLLIN, 0};
    bool closed = false;
    for (int i = 0; i < 50 && !closed; ++i) {
        if (poll(&p, 1, 100) > 0) {
            char buf[256];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            closed = n <= 0;
        }
    }
    EXPECT_TRUE(closed);
    close(fd);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), 0);
}

TEST(TlsTest, a_server_of_another_ca_is_refused) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8903);

    Pki foreign;
    IssueOptions options;
    options.uris = {
        "spiffe://" + domain +
        "/tenant/018f4e2a-0000-7000-8000-0000000000cc/"
        "client/vm1"
    };
    Identity foreign_client = foreign.issue("foreign-client", options);

    int fd = server.connect_raw();
    EXPECT_EQ(raw_handshake(fd, foreign, foreign_client, ""), EACCES);
    close(fd);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), 0);
}

TEST(TlsTest, a_client_of_another_ca_is_refused_by_the_server) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8904);

    // The foreign client trusts the real CA but holds a certificate the real
    // server does not trust.
    Pki foreign;
    IssueOptions options;
    options.uris = {
        "spiffe://" + domain +
        "/tenant/018f4e2a-0000-7000-8000-0000000000cc/"
        "client/vm1"
    };
    Identity foreign_client = foreign.issue("foreign-client", options);

    int fd = server.connect_raw();
    // The client side of TLS 1.3 completes before the server has judged its
    // certificate, so what shows is that the connection is dropped.
    raw_handshake(fd, tls.pki, foreign_client, ost_uri(ost_id));
    pollfd p{fd, POLLIN, 0};
    bool closed = false;
    for (int i = 0; i < 50 && !closed; ++i) {
        if (poll(&p, 1, 100) > 0) {
            char buf[256];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            closed = n <= 0;
        }
    }
    EXPECT_TRUE(closed);
    close(fd);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), 0);
}

TEST(TlsTest, the_wrong_ost_identity_is_refused) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8905);

    IssueOptions options;
    options.uris = {
        "spiffe://" + domain +
        "/tenant/018f4e2a-0000-7000-8000-0000000000cc/"
        "client/vm1"
    };
    Identity client = tls.pki.issue("client", options);

    int fd = server.connect_raw();
    EXPECT_EQ(
        raw_handshake(fd, tls.pki, client, ost_uri(other_ost_id)), EACCES
    );
    close(fd);

    fd = server.connect_raw();
    EXPECT_EQ(raw_handshake(fd, tls.pki, client, ost_uri(ost_id)), 0);
    close(fd);
}

TEST(TlsTest, a_renewed_certificate_is_used_after_a_reload) {
    rawstor::tests::TlsProcess tls(ost_uri(ost_id));
    OstServer server(8908);

    IssueOptions renewed_options;
    renewed_options.uris = {ost_uri(other_ost_id)};
    Identity renewed = tls.pki.issue("renewed", renewed_options);
    IssueOptions client_options;
    client_options.uris = {
        "spiffe://" + domain +
        "/tenant/018f4e2a-0000-7000-8000-0000000000cc/"
        "client/vm1"
    };
    Identity client = tls.pki.issue("client", client_options);

    int fd = server.connect_raw();
    EXPECT_EQ(raw_handshake(fd, tls.pki, client, ost_uri(ost_id)), 0);
    close(fd);

    std::filesystem::copy_file(
        renewed.cert_file, tls.identity.cert_file,
        std::filesystem::copy_options::overwrite_existing
    );
    std::filesystem::copy_file(
        renewed.key_file, tls.identity.key_file,
        std::filesystem::copy_options::overwrite_existing
    );
    rawstor_tls_request_reload();

    // Connections made from now on present the renewed certificate.
    fd = server.connect_raw();
    EXPECT_EQ(raw_handshake(fd, tls.pki, client, ost_uri(ost_id)), EACCES);
    close(fd);
    fd = server.connect_raw();
    EXPECT_EQ(raw_handshake(fd, tls.pki, client, ost_uri(other_ost_id)), 0);
    close(fd);
}
