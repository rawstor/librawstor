#include <array>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <rawstd/uuid.h>
#include <rawtls/authorization.hpp>
#include <string>
#include <system_error>

namespace {
const std::string tenant = "018f4e2a-0000-7000-8000-000000000001";
const std::string server = "018f4e2a-0000-7000-8000-000000000002";
class Connection : public rawtls::Transport {
    rawtls::SpiffeId _peer{
        "spiffe://cluster.example/tenant/" + tenant + "/client/test"
    };
    rawtls::SpiffeId _local{"spiffe://cluster.example/ost/" + server};

public:
    std::array<unsigned char, 32> digest{};
    uint64_t expiry = UINT64_MAX;
    const rawtls::SpiffeId* peer() const noexcept override { return &_peer; }
    const rawtls::SpiffeId* local() const noexcept override { return &_local; }
    uint64_t peer_expiry() const noexcept override { return expiry; }
    std::array<unsigned char, 32> fingerprint(bool) const override {
        return digest;
    }
    rawstd::Task<size_t> send(const void*, size_t, unsigned int) override {
        throw std::logic_error("unused");
        co_return 0;
    }
    rawstd::Task<size_t> sendmsg(const msghdr*, unsigned int) override {
        throw std::logic_error("unused");
        co_return 0;
    }
    rawio::RecvStream
    recv_multishot(size_t, unsigned int, size_t, unsigned int) override {
        throw std::logic_error("unused");
    }
    void cancel_recv_multishot() noexcept override {}
};
class AuthorizationTest : public ::testing::Test {
protected:
    std::string dir;
    std::string key, pub;
    Connection connection;
    RawstorCapability token{};
    void SetUp() override {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "rawstor-auth-XXXXXX")
                .string();
        ASSERT_NE(mkdtemp(pattern.data()), nullptr);
        dir = pattern;
        key = dir + "/key.pem";
        pub = dir + "/public.pem";
        EVP_PKEY* signing = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        ASSERT_NE(signing, nullptr);
        FILE* f = fopen(key.c_str(), "w");
        ASSERT_NE(f, nullptr);
        ASSERT_EQ(
            PEM_write_PrivateKey(
                f, signing, nullptr, nullptr, 0, nullptr, nullptr
            ),
            1
        );
        fclose(f);
        f = fopen(pub.c_str(), "w");
        ASSERT_NE(f, nullptr);
        ASSERT_EQ(PEM_write_PUBKEY(f, signing), 1);
        fclose(f);
        EVP_PKEY_free(signing);
        RawstdUUID id{};
        rawstd_uuid_from_string(&id, tenant.c_str());
        memcpy(token.tenant_id, id.bytes, 16);
        rawstd_uuid_from_string(&id, server.c_str());
        memcpy(token.server_id, id.bytes, 16);
        ASSERT_EQ(rawstd_uuid7_init(&id), 0);
        memcpy(token.object_id, id.bytes, 16);
        token.not_after = static_cast<uint64_t>(time(nullptr)) + 300;
        token.rights = RAWSTOR_RIGHT_ALL;
        token = rawtls::sign_capability(token, key);
    }
    void TearDown() override {
        unsetenv("RAWSTOR_AUTH_KEYS");
        std::filesystem::remove_all(dir);
    }
};
TEST_F(AuthorizationTest, signed_capability_binds_all_fields) {
    EXPECT_NO_THROW(
        rawtls::verify_capability(token, pub, connection, time(nullptr))
    );
    // Every byte is authenticated, including the scope, expiry, rights and key
    // ID.
    for (size_t i = 0; i < sizeof(token); ++i) {
        auto changed = token;
        reinterpret_cast<unsigned char*>(&changed)[i] ^= 1;
        EXPECT_THROW(
            rawtls::verify_capability(changed, pub, connection, time(nullptr)),
            std::system_error
        ) << i;
    }
    auto expired = token;
    expired.not_after = time(nullptr);
    expired = rawtls::sign_capability(expired, key);
    EXPECT_THROW(
        rawtls::verify_capability(expired, pub, connection, time(nullptr)),
        std::system_error
    );
    connection.digest[0] = 1;
    EXPECT_THROW(
        rawtls::verify_capability(token, pub, connection, time(nullptr)),
        std::system_error
    );
}
TEST_F(AuthorizationTest, rights_and_scope_are_checked_after_installation) {
    setenv("RAWSTOR_AUTH_KEYS", pub.c_str(), 1);
    rawtls::Authorization auth;
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_READ, token.object_id, 0, nullptr),
        EACCES
    );
    token.rights = RAWSTOR_RIGHT_READ;
    token = rawtls::sign_capability(token, key);
    auth.renew(token, connection);
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_READ, token.object_id, 0, nullptr), 0
    );
    EXPECT_EQ(
        auth.check(
            connection, RAWSTOR_CMD_SET_OBJECT, token.object_id, 0, nullptr,
            RAWSTOR_READONLY
        ),
        0
    );
    EXPECT_EQ(
        auth.check(
            connection, RAWSTOR_CMD_SET_OBJECT, token.object_id, 0, nullptr, 0
        ),
        EACCES
    );
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_WRITE, token.object_id, 0, nullptr),
        EACCES
    );
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_LIST, token.object_id, 0, nullptr),
        EACCES
    );
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_READ, token.object_id, 1, nullptr),
        ENOENT
    );
    uint8_t wrong[16]{};
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_READ, wrong, 0, nullptr), ENOENT
    );
    wrong[0] = 1;
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_READ, token.object_id, 0, wrong),
        ENOENT
    );
    EXPECT_EQ(
        auth.check(connection, UINT16_MAX, token.object_id, 0, nullptr), EACCES
    );
    connection.expiry = static_cast<uint64_t>(time(nullptr));
    EXPECT_EQ(
        auth.check(connection, RAWSTOR_CMD_READ, token.object_id, 0, nullptr),
        EACCES
    );
}
TEST(AuthorizationPolicyTest, closed_provider_table) {
    using rawtls::Role;
    EXPECT_TRUE(rawtls::provider_member(Role::mds, RAWSTOR_CMD_META));
    EXPECT_TRUE(rawtls::provider_member(Role::admin, RAWSTOR_CMD_ALLOCATE));
    EXPECT_FALSE(rawtls::provider_member(Role::admin, RAWSTOR_CMD_WRITE));
    EXPECT_FALSE(rawtls::provider_member(Role::mds, RAWSTOR_CMD_ALLOCATE));
    EXPECT_FALSE(rawtls::provider_member(Role::ost, RAWSTOR_CMD_READ));
    EXPECT_FALSE(rawtls::provider_member(Role::admin, UINT16_MAX));
    EXPECT_EQ(
        rawtls::member_right(RAWSTOR_CMD_WRITE_ZEROES, RAWSTOR_FLAG_UNMAP),
        RAWSTOR_RIGHT_DISCARD
    );
    EXPECT_EQ(
        rawtls::member_right(RAWSTOR_CMD_SYNC_ACCEPT), RAWSTOR_RIGHT_WRITE
    );
}
} // namespace
