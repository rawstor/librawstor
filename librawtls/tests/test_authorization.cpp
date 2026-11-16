#include <rawtls/authorization.hpp>

#include <rawstd/uuid.h>

#include <gtest/gtest.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>

#include <cstring>
#include <memory>
#include <system_error>

namespace {
const std::string tenant = "018f4e2a-0000-7000-8000-000000000001";
const std::string object = "018f4e2a-0000-7000-8000-000000000002";

class Connection : public rawtls::Transport {
public:
    rawtls::SpiffeId identity{
        "spiffe://cluster.example/tenant/" + tenant + "/client/test"
    };
    uint64_t expiry = UINT64_MAX;

    const rawtls::SpiffeId* peer() const noexcept override { return &identity; }

    uint64_t peer_expiry() const noexcept override { return expiry; }

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

using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
} // namespace

TEST(AuthorizationTest, roles_are_intersected_with_object_masks) {
    Connection connection;
    rawtls::Authorization authorization;
    RawstdUUID id{};
    ASSERT_EQ(rawstd_uuid_from_string(&id, object.c_str()), 0);
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_READ, id.bytes, 0, nullptr),
        EACCES
    );
    connection.identity.permissions(
        {RAWSTOR_ACCESS_WRITER,
         {{object, RAWSTOR_RIGHT_READ | RAWSTOR_RIGHT_MANAGE}}}
    );
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_READ, id.bytes, 0, nullptr),
        0
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_WRITE, id.bytes, 0, nullptr
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_RELEASE, id.bytes, 0, nullptr
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_FREEZE, id.bytes, 0, nullptr
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_LOCATION_INFO, nullptr, 0, nullptr
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_SET_OWNER, id.bytes, 0, nullptr
        ),
        EACCES
    );
    RawstdUUID other{};
    ASSERT_EQ(rawstd_uuid7_init(&other), 0);
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_WRITE, other.bytes, 0, nullptr
        ),
        0
    );
}

TEST(AuthorizationTest, expired_certificates_and_foreign_owners_are_denied) {
    Connection connection;
    connection.identity.permissions({RAWSTOR_ACCESS_MANAGER, {}});
    rawtls::Authorization authorization;
    RawstdUUID owner{}, other{};
    ASSERT_EQ(rawstd_uuid_from_string(&owner, tenant.c_str()), 0);
    ASSERT_EQ(rawstd_uuid7_init(&other), 0);
    EXPECT_EQ(authorization.owner(connection, owner.bytes), 0);
    EXPECT_EQ(authorization.owner(connection, other.bytes), ENOENT);
    connection.expiry = 1;
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_READ, nullptr, 0, nullptr),
        EACCES
    );
    connection.identity =
        rawtls::SpiffeId("spiffe://cluster.example/admin/operator");
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_META, nullptr, 0, nullptr),
        EACCES
    );
}

TEST(AuthorizationTest, snapshots_remain_readonly_for_managers) {
    Connection connection;
    connection.identity.permissions({RAWSTOR_ACCESS_MANAGER, {}});
    rawtls::Authorization authorization;
    RawstdUUID version{};
    ASSERT_EQ(rawstd_uuid7_init(&version), 0);
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_SET_OBJECT, nullptr, 0, version.bytes,
            RAWSTOR_READONLY
        ),
        0
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_WRITE, nullptr, 0, version.bytes
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_DISCARD, nullptr, 0, version.bytes
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_RELEASE, nullptr, 0, version.bytes
        ),
        0
    );
}

TEST(
    AuthorizationTest,
    certificate_policy_roundtrips_and_missing_policy_grants_nothing
) {
    Cert certificate(X509_new(), X509_free);
    ASSERT_NE(certificate, nullptr);
    EXPECT_EQ(rawtls::certificate_permissions(certificate.get()).rights(), 0u);
    rawtls::Permissions policy{RAWSTOR_ACCESS_MANAGER, {{object, 0}}};
    rawtls::certificate_permissions(certificate.get(), policy);
    auto decoded = rawtls::certificate_permissions(certificate.get());
    EXPECT_EQ(decoded.role, policy.role);
    EXPECT_EQ(decoded.objects, policy.objects);
    RawstdUUID id{};
    ASSERT_EQ(rawstd_uuid_from_string(&id, object.c_str()), 0);
    EXPECT_EQ(decoded.rights(id.bytes), 0u);
    EXPECT_EQ(decoded.rights(), RAWSTOR_RIGHT_ALL);
}

TEST(
    AuthorizationTest, duplicate_and_malformed_certificate_policies_fail_closed
) {
    Cert certificate(X509_new(), X509_free);
    rawtls::certificate_permissions(
        certificate.get(), {RAWSTOR_ACCESS_READER, {}}
    );
    ASSERT_EQ(X509_get_ext_count(certificate.get()), 1);
    ASSERT_EQ(
        X509_add_ext(certificate.get(), X509_get_ext(certificate.get(), 0), -1),
        1
    );
    EXPECT_THROW(
        rawtls::certificate_permissions(certificate.get()), std::system_error
    );
    X509_EXTENSION_free(X509_delete_ext(certificate.get(), 1));
    auto data = X509_EXTENSION_get_data(X509_get_ext(certificate.get(), 0));
    unsigned char broken[] = {0x0c, 0x7f, 0x00};
    ASSERT_EQ(ASN1_OCTET_STRING_set(data, broken, sizeof(broken)), 1);
    EXPECT_THROW(
        rawtls::certificate_permissions(certificate.get()), std::system_error
    );
}

TEST(AuthorizationTest, invalid_policy_cannot_be_issued) {
    Cert certificate(X509_new(), X509_free);
    EXPECT_THROW(
        rawtls::certificate_permissions(certificate.get(), {99, {}}),
        std::system_error
    );
    EXPECT_THROW(
        rawtls::certificate_permissions(
            certificate.get(), {RAWSTOR_ACCESS_READER, {{object, 16}}}
        ),
        std::system_error
    );
    EXPECT_THROW(
        rawtls::certificate_permissions(
            certificate.get(), {RAWSTOR_ACCESS_READER, {{"not-a-uuid", 1}}}
        ),
        std::system_error
    );
    EXPECT_THROW(
        rawtls::certificate_permissions(certificate.get(), {0, {{object, 1}}}),
        std::system_error
    );
}
