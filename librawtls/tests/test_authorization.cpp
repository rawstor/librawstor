#include <rawstor/pki.h>
#include <rawtls/authorization.hpp>

#include <rawstd/uuid.h>

#include <gtest/gtest.h>
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

TEST(
    AuthorizationTest, provider_admin_can_manage_membership_without_data_writes
) {
    Connection connection;
    rawtls::Authorization authorization;
    connection.identity =
        rawtls::SpiffeId("spiffe://cluster.example/admin/operator");
    for (auto command : {RAWSTOR_CMD_SYNC_PREPARE, RAWSTOR_CMD_SYNC_ACCEPT}) {
        EXPECT_EQ(
            authorization.check(connection, command, nullptr, 0, nullptr), 0
        );
        EXPECT_FALSE(rawtls::provider_member(rawtls::Role::mds, command));
        EXPECT_FALSE(rawtls::provider_member(rawtls::Role::ost, command));
    }
    for (auto command :
         {RAWSTOR_CMD_WRITE, RAWSTOR_CMD_DISCARD, RAWSTOR_CMD_WRITE_ZEROES,
          RAWSTOR_CMD_FLUSH, RAWSTOR_CMD_LEAVE})
        EXPECT_EQ(
            authorization.check(connection, command, nullptr, 0, nullptr),
            EACCES
        );
}

TEST(AuthorizationTest, object_masks_override_role_defaults) {
    Connection connection;
    rawtls::Authorization authorization;
    RawstdUUID id{};
    ASSERT_EQ(rawstd_uuid_from_string(&id, object.c_str()), 0);
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_READ, id.bytes, 0, nullptr),
        EACCES
    );
    connection.identity.permissions(
        {RAWSTOR_ROLE_WRITER,
         {{object, RAWSTOR_PERM_READ | RAWSTOR_PERM_MANAGE}}}
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
        0
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_FREEZE, id.bytes, 0, nullptr
        ),
        0
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
    connection.identity.permissions({RAWSTOR_ROLE_MANAGER, {}});
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
    connection.identity.permissions({RAWSTOR_ROLE_MANAGER, {}});
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
    EXPECT_EQ(rawtls::certificate_permissions(certificate.get()).mask(), 0u);
    rawtls::Permissions policy{RAWSTOR_ROLE_MANAGER, {{object, 0}}};
    rawtls::certificate_permissions(certificate.get(), policy);
    auto decoded = rawtls::certificate_permissions(certificate.get());
    EXPECT_EQ(decoded.role, policy.role);
    EXPECT_EQ(decoded.objects, policy.objects);
    RawstdUUID id{};
    ASSERT_EQ(rawstd_uuid_from_string(&id, object.c_str()), 0);
    EXPECT_EQ(decoded.mask(id.bytes), 0u);
    EXPECT_EQ(decoded.mask(), RAWSTOR_PERM_ALL);
}

TEST(
    AuthorizationTest, duplicate_and_malformed_certificate_policies_fail_closed
) {
    Cert certificate(X509_new(), X509_free);
    rawtls::certificate_permissions(
        certificate.get(), {RAWSTOR_ROLE_READER, {}}
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
            certificate.get(), {RAWSTOR_ROLE_READER, {{object, 16}}}
        ),
        std::system_error
    );
    EXPECT_THROW(
        rawtls::certificate_permissions(
            certificate.get(), {RAWSTOR_ROLE_READER, {{"not-a-uuid", 1}}}
        ),
        std::system_error
    );
}

TEST(AuthorizationTest, none_grants_only_explicit_object_permissions) {
    Cert certificate(X509_new(), X509_free);
    rawtls::certificate_permissions(
        certificate.get(), {RAWSTOR_ROLE_NONE, {{object, 7}}}
    );
    auto policy = rawtls::certificate_permissions(certificate.get());
    EXPECT_EQ(policy.role, RAWSTOR_ROLE_NONE);
    EXPECT_EQ(policy.mask(), 0u);
    RawstdUUID id{}, other{};
    ASSERT_EQ(rawstd_uuid_from_string(&id, object.c_str()), 0);
    ASSERT_EQ(rawstd_uuid7_init(&other), 0);
    EXPECT_EQ(policy.mask(id.bytes), 7u);
    EXPECT_EQ(policy.mask(other.bytes), 0u);
    Connection connection;
    connection.identity.permissions(policy);
    rawtls::Authorization authorization;
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_READ, id.bytes, 0, nullptr),
        0
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_WRITE, id.bytes, 0, nullptr
        ),
        0
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_DISCARD, id.bytes, 0, nullptr
        ),
        0
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_RELEASE, id.bytes, 0, nullptr
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(
            connection, RAWSTOR_CMD_READ, other.bytes, 0, nullptr
        ),
        EACCES
    );
    EXPECT_EQ(
        authorization.check(connection, RAWSTOR_CMD_LIST, nullptr, 0, nullptr),
        EACCES
    );
}
