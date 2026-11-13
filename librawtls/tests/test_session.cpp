#include <gtest/gtest.h>

#include <rawtls/context.hpp>
#include <rawtls/session.hpp>

#include "pki.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <system_error>
#include <vector>

namespace {

using rawtls::testing::Identity;
using rawtls::testing::IssueOptions;
using rawtls::testing::Pki;

const std::string domain = "cluster.example";
const std::string ost_a = "0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";
const std::string ost_b = "0198f1a2-3b4c-7d5e-8f90-b1b2c3d4e5f6";
const std::string tenant = "0198f1a2-3b4c-7d5e-8f90-0123456789ab";

std::string ost_uri(const std::string& id) {
    return "spiffe://" + domain + "/ost/" + id;
}

std::string client_uri() {
    return "spiffe://" + domain + "/tenant/" + tenant + "/client/vm42";
}

IssueOptions with_uri(const std::string& uri) {
    IssueOptions options;
    options.uris = {uri};
    return options;
}

rawtls::Config
config(const Pki& pki, const Identity& identity, const std::string& crl = "") {
    rawtls::Config c;
    c.trust_domain = domain;
    c.cert_file = identity.cert_file;
    c.key_file = identity.key_file;
    c.ca_file = pki.ca_file();
    c.crl_file = crl;
    return c;
}

// Everything `from` has to say goes to `to`.
void transfer(rawtls::Session& from, rawtls::Session& to) {
    std::vector<char> bytes(from.output_size());
    size_t n = from.take_output(bytes.data(), bytes.size());
    to.feed(bytes.data(), n);
}

struct Handshake {
    int client = 0;
    int server = 0;
};

// Runs the handshake between the two, carrying what each side says to the
// other, and reports the error each side ended with (0 for none).
Handshake handshake(rawtls::Session& client, rawtls::Session& server) {
    Handshake result;
    bool client_done = false;
    bool server_done = false;
    for (int round = 0; round < 10 && !(client_done && server_done); ++round) {
        try {
            client_done = client.handshake();
        } catch (const std::system_error& e) {
            result.client = e.code().value();
            transfer(client, server);
            return result;
        }
        transfer(client, server);
        try {
            server_done = server.handshake();
        } catch (const std::system_error& e) {
            result.server = e.code().value();
            transfer(server, client);
            return result;
        }
        transfer(server, client);
    }
    return result;
}

std::string decrypt_all(rawtls::Session& session) {
    std::string out;
    char buf[4096];
    for (;;) {
        size_t n = session.decrypt(buf, sizeof(buf));
        if (n == 0) {
            return out;
        }
        out.append(buf, n);
    }
}

class SessionTest : public ::testing::Test {
protected:
    Pki pki;
    Identity server_identity;
    Identity client_identity;

    void SetUp() override {
        server_identity = pki.issue("server", with_uri(ost_uri(ost_a)));
        client_identity = pki.issue("client", with_uri(client_uri()));
    }

    // A handshake between a client holding `client_identity` that expects
    // `expected` and a server holding `server_identity`.
    Handshake
    run(const std::string& expected, const Identity& client_id,
        const Identity& server_id) {
        rawtls::Context client_context(config(pki, client_id));
        rawtls::Context server_context(config(pki, server_id));
        rawtls::Session client(
            client_context, rawtls::Session::Mode::client, expected
        );
        rawtls::Session server(server_context, rawtls::Session::Mode::server);
        return handshake(client, server);
    }
};

} // namespace

TEST_F(SessionTest, MutualHandshakeNamesBothPeers) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);

    Handshake result = handshake(client, server);

    EXPECT_EQ(result.client, 0);
    EXPECT_EQ(result.server, 0);
    EXPECT_TRUE(client.handshake_done());
    EXPECT_TRUE(server.handshake_done());
    EXPECT_EQ(client.peer().role, rawtls::Role::ost);
    EXPECT_EQ(client.peer().name, ost_a);
    EXPECT_EQ(server.peer().role, rawtls::Role::client);
    EXPECT_EQ(server.peer().tenant, tenant);
    EXPECT_EQ(server.peer().name, "vm42");
}

TEST_F(SessionTest, DataGoesBothWays) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    ASSERT_EQ(handshake(client, server).client, 0);

    client.encrypt("hello", 5);
    transfer(client, server);
    EXPECT_EQ(decrypt_all(server), "hello");

    server.encrypt("world!", 6);
    transfer(server, client);
    EXPECT_EQ(decrypt_all(client), "world!");
}

TEST_F(SessionTest, PayloadArrivingInPieces) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    ASSERT_EQ(handshake(client, server).client, 0);

    std::string payload(1 << 20, '\0');
    std::mt19937 gen(1);
    for (char& c : payload) {
        c = static_cast<char>(gen());
    }
    client.encrypt(payload.data(), payload.size());

    std::vector<char> wire(client.output_size());
    ASSERT_EQ(client.take_output(wire.data(), wire.size()), wire.size());
    EXPECT_GT(wire.size(), payload.size());

    std::string received;
    for (size_t at = 0; at < wire.size(); at += 1000) {
        size_t n = std::min<size_t>(1000, wire.size() - at);
        server.feed(wire.data() + at, n);
        received += decrypt_all(server);
    }
    EXPECT_EQ(received, payload);
}

TEST_F(SessionTest, CloseNotify) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    ASSERT_EQ(handshake(client, server).client, 0);

    client.encrypt("bye", 3);
    client.shutdown();
    transfer(client, server);

    EXPECT_EQ(decrypt_all(server), "bye");
    EXPECT_TRUE(server.closed());
}

TEST_F(SessionTest, WrongServerIdentityIsRefused) {
    Handshake result = run(ost_uri(ost_b), client_identity, server_identity);
    EXPECT_EQ(result.client, EACCES);
}

TEST_F(SessionTest, ServerInAnotherTrustDomainIsRefused) {
    Identity other = pki.issue(
        "other-domain", with_uri("spiffe://other.example/ost/" + ost_a)
    );
    Handshake result = run(ost_uri(ost_a), client_identity, other);
    EXPECT_EQ(result.client, EACCES);
}

TEST_F(SessionTest, ClientInAnotherTrustDomainIsRefused) {
    Identity other = pki.issue(
        "other-client",
        with_uri("spiffe://other.example/tenant/" + tenant + "/client/vm42")
    );
    Handshake result = run(ost_uri(ost_a), other, server_identity);
    EXPECT_EQ(result.server, EACCES);
}

TEST_F(SessionTest, ServerWithAClientIdentityIsRefused) {
    Identity impostor = pki.issue("impostor", with_uri(client_uri()));
    Handshake result = run(ost_uri(ost_a), client_identity, impostor);
    EXPECT_EQ(result.client, EACCES);
}

TEST_F(SessionTest, CertificateOfAnotherCaIsRefused) {
    Pki foreign;
    Identity foreign_server =
        foreign.issue("foreign-server", with_uri(ost_uri(ost_a)));
    Identity foreign_client =
        foreign.issue("foreign-client", with_uri(client_uri()));

    EXPECT_EQ(
        run(ost_uri(ost_a), client_identity, foreign_server).client, EACCES
    );
    EXPECT_EQ(
        run(ost_uri(ost_a), foreign_client, server_identity).server, EACCES
    );
}

TEST_F(SessionTest, ExpiredCertificateIsRefused) {
    IssueOptions options = with_uri(ost_uri(ost_a));
    options.not_before = -7200;
    options.not_after = -3600;
    Identity expired = pki.issue("expired", options);
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, expired).client, EACCES);
}

TEST_F(SessionTest, CertificateNotYetValidIsRefused) {
    IssueOptions options = with_uri(ost_uri(ost_a));
    options.not_before = 3600;
    options.not_after = 7200;
    Identity early = pki.issue("early", options);
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, early).client, EACCES);
}

TEST_F(SessionTest, NoUriSanIsRefused) {
    Identity bare = pki.issue("bare", IssueOptions());
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, bare).client, EACCES);
}

TEST_F(SessionTest, SeveralUriSansAreRefused) {
    IssueOptions options;
    options.uris = {ost_uri(ost_a), ost_uri(ost_b)};
    Identity two = pki.issue("two", options);
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, two).client, EACCES);
}

TEST_F(SessionTest, UriSanThatIsNotAnIdIsRefused) {
    Identity web = pki.issue("web", with_uri("https://example.com/ost"));
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, web).client, EACCES);
}

TEST_F(SessionTest, MissingExtendedKeyUsageIsRefused) {
    IssueOptions options = with_uri(ost_uri(ost_a));
    options.usage = false;
    Identity unrestricted = pki.issue("unrestricted", options);
    EXPECT_EQ(
        run(ost_uri(ost_a), client_identity, unrestricted).client, EACCES
    );
}

TEST_F(SessionTest, ExtendedKeyUsageOfTheOtherEndIsRefused) {
    IssueOptions as_client = with_uri(ost_uri(ost_a));
    as_client.server_auth = false;
    Identity client_only = pki.issue("client-only", as_client);
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, client_only).client, EACCES);

    IssueOptions as_server = with_uri(client_uri());
    as_server.client_auth = false;
    Identity server_only = pki.issue("server-only", as_server);
    EXPECT_EQ(run(ost_uri(ost_a), server_only, server_identity).server, EACCES);
}

TEST_F(SessionTest, CaCertificateAsALeafIsRefused) {
    IssueOptions options = with_uri(ost_uri(ost_a));
    options.ca = true;
    Identity ca_leaf = pki.issue("ca-leaf", options);
    EXPECT_EQ(run(ost_uri(ost_a), client_identity, ca_leaf).client, EACCES);
}

TEST_F(SessionTest, RefusedClientLearnsOnTheNextRead) {
    Identity other = pki.issue(
        "other-client",
        with_uri("spiffe://other.example/tenant/" + tenant + "/client/vm42")
    );
    rawtls::Context client_context(config(pki, other));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);

    Handshake result = handshake(client, server);
    EXPECT_EQ(result.server, EACCES);
    EXPECT_TRUE(client.handshake_done());

    char buf[16];
    try {
        client.decrypt(buf, sizeof(buf));
        FAIL() << "the alert did not arrive";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EPROTO);
    }
}

TEST_F(SessionTest, RevokedCertificateIsRefused) {
    std::string crl = pki.crl({server_identity.serial});
    rawtls::Context client_context(config(pki, client_identity, crl));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    EXPECT_EQ(handshake(client, server).client, EACCES);
}

TEST_F(SessionTest, CertificateNotOnTheCrlIsAccepted) {
    std::string crl = pki.crl({server_identity.serial + 100});
    rawtls::Context client_context(config(pki, client_identity, crl));
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    Handshake result = handshake(client, server);
    EXPECT_EQ(result.client, 0);
    EXPECT_EQ(result.server, 0);
}

TEST_F(SessionTest, TlsOneTwoIsRefused) {
    rawtls::Context server_context(config(pki, server_identity));
    rawtls::Session server(server_context, rawtls::Session::Mode::server);

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
    server.feed(hello.data(), hello.size());
    try {
        server.handshake();
        FAIL() << "a TLS 1.2 client was accepted";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EPROTO);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
}

TEST_F(SessionTest, ReloadServesNewSessionsWithTheNewCertificate) {
    Identity renewed = pki.issue("renewed", with_uri(ost_uri(ost_b)));
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));

    {
        rawtls::Session client(
            client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
        );
        rawtls::Session server(server_context, rawtls::Session::Mode::server);
        ASSERT_EQ(handshake(client, server).client, 0);

        // An established session keeps going over a reload.
        std::filesystem::copy_file(
            renewed.cert_file, server_identity.cert_file,
            std::filesystem::copy_options::overwrite_existing
        );
        std::filesystem::copy_file(
            renewed.key_file, server_identity.key_file,
            std::filesystem::copy_options::overwrite_existing
        );
        server_context.reload();
        client.encrypt("still here", 10);
        transfer(client, server);
        EXPECT_EQ(decrypt_all(server), "still here");
    }

    rawtls::Session old_client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session new_server(server_context, rawtls::Session::Mode::server);
    EXPECT_EQ(handshake(old_client, new_server).client, EACCES);

    rawtls::Session new_client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_b)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    Handshake result = handshake(new_client, server);
    EXPECT_EQ(result.client, 0);
    EXPECT_EQ(result.server, 0);
}

TEST_F(SessionTest, FailedReloadKeepsTheContext) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));

    {
        std::ofstream broken(server_identity.key_file, std::ios::trunc);
        broken << "not a key\n";
    }
    try {
        server_context.reload();
        FAIL() << "a broken key was accepted";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EINVAL);
    }

    rawtls::Session client(
        client_context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    rawtls::Session server(server_context, rawtls::Session::Mode::server);
    Handshake result = handshake(client, server);
    EXPECT_EQ(result.client, 0);
    EXPECT_EQ(result.server, 0);
}

TEST_F(SessionTest, ContextRejectsBrokenFiles) {
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

TEST_F(SessionTest, ClientNeedsAnExpectedServerIdentity) {
    rawtls::Context context(config(pki, client_identity));
    EXPECT_THROW(
        rawtls::Session(context, rawtls::Session::Mode::client),
        std::system_error
    );
    EXPECT_THROW(
        rawtls::Session(context, rawtls::Session::Mode::client, "nonsense"),
        std::system_error
    );
    // The server it expects must be an OST or an MDS.
    EXPECT_THROW(
        rawtls::Session(context, rawtls::Session::Mode::client, client_uri()),
        std::system_error
    );
}

TEST_F(SessionTest, ClientMayExpectOnlyTheRoleOfTheServer) {
    rawtls::Context client_context(config(pki, client_identity));
    rawtls::Context server_context(config(pki, server_identity));
    {
        rawtls::Session client(
            client_context, rawtls::Session::Mode::client, "", rawtls::Role::ost
        );
        rawtls::Session server(server_context, rawtls::Session::Mode::server);
        Handshake result = handshake(client, server);
        EXPECT_EQ(result.client, 0);
        EXPECT_EQ(client.peer().name, ost_a);
    }
    {
        rawtls::Session client(
            client_context, rawtls::Session::Mode::client, "", rawtls::Role::mds
        );
        rawtls::Session server(server_context, rawtls::Session::Mode::server);
        EXPECT_EQ(handshake(client, server).client, EACCES);
    }
    // Only the roles of a server can be expected of one.
    EXPECT_THROW(
        rawtls::Session(
            client_context, rawtls::Session::Mode::client, "",
            rawtls::Role::admin
        ),
        std::system_error
    );
}

TEST_F(SessionTest, NothingFlowsBeforeTheHandshake) {
    rawtls::Context context(config(pki, client_identity));
    rawtls::Session client(
        context, rawtls::Session::Mode::client, ost_uri(ost_a)
    );
    char buf[8];
    EXPECT_THROW(client.encrypt("x", 1), std::system_error);
    EXPECT_THROW(client.decrypt(buf, sizeof(buf)), std::system_error);
    EXPECT_THROW(client.peer(), std::system_error);
}
