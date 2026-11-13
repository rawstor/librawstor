#include <gtest/gtest.h>

#include <rawtls/spiffe.hpp>

#include <cerrno>
#include <string>
#include <system_error>

namespace {

const std::string uuid_a = "0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";
const std::string uuid_b = "0198f1a2-3b4c-7d5e-8f90-0123456789ab";

void expect_rejected(const std::string& uri) {
    try {
        rawtls::SpiffeId::parse(uri);
        FAIL() << "accepted " << uri;
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EINVAL) << uri;
    }
}

} // namespace

TEST(SpiffeTest, Ost) {
    rawtls::SpiffeId id =
        rawtls::SpiffeId::parse("spiffe://cluster.example/ost/" + uuid_a);
    EXPECT_EQ(id.role, rawtls::Role::ost);
    EXPECT_EQ(id.trust_domain, "cluster.example");
    EXPECT_EQ(id.name, uuid_a);
    EXPECT_TRUE(id.tenant.empty());
    EXPECT_TRUE(id.is_server());
}

TEST(SpiffeTest, Mds) {
    rawtls::SpiffeId id =
        rawtls::SpiffeId::parse("spiffe://cluster.example/mds/mds-1");
    EXPECT_EQ(id.role, rawtls::Role::mds);
    EXPECT_EQ(id.name, "mds-1");
    EXPECT_TRUE(id.is_server());
}

TEST(SpiffeTest, Admin) {
    rawtls::SpiffeId id =
        rawtls::SpiffeId::parse("spiffe://cluster.example/admin/ops_2");
    EXPECT_EQ(id.role, rawtls::Role::admin);
    EXPECT_EQ(id.name, "ops_2");
    EXPECT_FALSE(id.is_server());
}

TEST(SpiffeTest, Client) {
    std::string uri =
        "spiffe://cluster.example/tenant/" + uuid_b + "/client/vm42.disk0";
    rawtls::SpiffeId id = rawtls::SpiffeId::parse(uri);
    EXPECT_EQ(id.role, rawtls::Role::client);
    EXPECT_EQ(id.tenant, uuid_b);
    EXPECT_EQ(id.name, "vm42.disk0");
    EXPECT_EQ(id.uri, uri);
    EXPECT_FALSE(id.is_server());
}

TEST(SpiffeTest, NamesAreCaseSensitive) {
    rawtls::SpiffeId id =
        rawtls::SpiffeId::parse("spiffe://cluster.example/mds/MDS-One");
    EXPECT_EQ(id.name, "MDS-One");
}

TEST(SpiffeTest, Scheme) {
    expect_rejected("");
    expect_rejected("cluster.example/mds/a");
    expect_rejected("https://cluster.example/mds/a");
    expect_rejected("SPIFFE://cluster.example/mds/a");
    expect_rejected("spiffe:/cluster.example/mds/a");
}

TEST(SpiffeTest, TrustDomain) {
    expect_rejected("spiffe:///mds/a");
    expect_rejected("spiffe://cluster.example");
    expect_rejected("spiffe://Cluster.Example/mds/a");
    expect_rejected("spiffe://cluster.example:8080/mds/a");
    expect_rejected("spiffe://user@cluster.example/mds/a");
    expect_rejected("spiffe://cluster example/mds/a");
    expect_rejected("spiffe://" + std::string(256, 'a') + "/mds/a");
    EXPECT_NO_THROW(
        rawtls::SpiffeId::parse("spiffe://" + std::string(255, 'a') + "/mds/a")
    );
}

TEST(SpiffeTest, Path) {
    expect_rejected("spiffe://cluster.example/");
    expect_rejected("spiffe://cluster.example/mds");
    expect_rejected("spiffe://cluster.example/mds/");
    expect_rejected("spiffe://cluster.example/mds/a/");
    expect_rejected("spiffe://cluster.example/mds//a");
    expect_rejected("spiffe://cluster.example/mds/.");
    expect_rejected("spiffe://cluster.example/mds/..");
    expect_rejected("spiffe://cluster.example/mds/a?x=1");
    expect_rejected("spiffe://cluster.example/mds/a#x");
    expect_rejected("spiffe://cluster.example/mds/a%20b");
    expect_rejected("spiffe://cluster.example/mds/a b");
    expect_rejected(std::string("spiffe://cluster.example/mds/a\0b", 33));
}

TEST(SpiffeTest, Shape) {
    expect_rejected("spiffe://cluster.example/user/a");
    expect_rejected("spiffe://cluster.example/ost");
    expect_rejected("spiffe://cluster.example/ost/" + uuid_a + "/extra");
    expect_rejected("spiffe://cluster.example/mds/a/b");
    expect_rejected("spiffe://cluster.example/admin/a/b");
    expect_rejected("spiffe://cluster.example/tenant/" + uuid_b);
    expect_rejected("spiffe://cluster.example/tenant/" + uuid_b + "/client");
    expect_rejected(
        "spiffe://cluster.example/tenant/" + uuid_b + "/client/a/b"
    );
    expect_rejected("spiffe://cluster.example/tenant/" + uuid_b + "/admin/a");
    expect_rejected("spiffe://cluster.example/client/a");
}

TEST(SpiffeTest, Uuids) {
    expect_rejected("spiffe://cluster.example/ost/not-a-uuid");
    expect_rejected("spiffe://cluster.example/ost/mds-1");
    expect_rejected(
        "spiffe://cluster.example/ost/00000000-0000-0000-0000-000000000000"
    );
    expect_rejected(
        "spiffe://cluster.example/ost/0198F1A2-3B4C-7D5E-8F90-A1B2C3D4E5F6"
    );
    expect_rejected(
        "spiffe://cluster.example/tenant/"
        "00000000-0000-0000-0000-000000000000/client/a"
    );
    expect_rejected("spiffe://cluster.example/tenant/team/client/a");
}

TEST(SpiffeTest, Length) {
    std::string prefix = "spiffe://cluster.example/mds/";
    EXPECT_NO_THROW(
        rawtls::SpiffeId::parse(prefix + std::string(2048 - prefix.size(), 'a'))
    );
    expect_rejected(prefix + std::string(2049 - prefix.size(), 'a'));
}
