#include <rawstor/pki.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <string>
#include <system_error>

#include <stdlib.h>

namespace {

namespace fs = std::filesystem;

const char* const ost_id = "0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";
const char* const mds_id = "0198f1a2-3b4c-7d5e-8f90-fedcba987654";

class PkiTest : public ::testing::Test {
protected:
    fs::path dir;
    char identity[RAWSTOR_PKI_IDENTITY_SIZE];

    void SetUp() override {
        std::string pattern =
            (fs::temp_directory_path() / "rawstor-pki-XXXXXX").string();
        ASSERT_NE(mkdtemp(pattern.data()), nullptr);
        dir = pattern;
        identity[0] = '\0';
    }

    void TearDown() override {
        std::error_code ignored;
        fs::remove_all(dir, ignored);
    }

    std::string path(const char* name) const { return (dir / name).string(); }
};

} // namespace

TEST_F(PkiTest, a_ca_issues_and_renews) {
    std::string ca = path("ca");
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), 0);
    EXPECT_TRUE(fs::exists(ca + "/ca.crt"));
    EXPECT_TRUE(fs::exists(ca + "/ca.key"));

    std::string cert = path("ost.crt");
    std::string key = path("ost.key");
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, ost_id, 3600, cert.c_str(),
            key.c_str(), identity, sizeof(identity), nullptr
        ),
        0
    );
    EXPECT_EQ(
        std::string(identity),
        std::string("spiffe://cluster.example/ost/") + ost_id
    );
    EXPECT_TRUE(fs::exists(cert));
    EXPECT_TRUE(fs::exists(key));

    identity[0] = '\0';
    ASSERT_EQ(
        rawstor_pki_renew(
            ca.c_str(), cert.c_str(), key.c_str(), 3600, identity,
            sizeof(identity)
        ),
        0
    );
    EXPECT_EQ(
        std::string(identity),
        std::string("spiffe://cluster.example/ost/") + ost_id
    );
}

TEST_F(PkiTest, an_ost_without_a_name_gets_an_id) {
    std::string ca = path("ca");
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), 0);
    std::string cert = path("ost.crt");
    std::string key = path("ost.key");
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, nullptr, 3600, cert.c_str(),
            key.c_str(), identity, sizeof(identity), nullptr
        ),
        0
    );
    EXPECT_EQ(
        std::string(identity).rfind("spiffe://cluster.example/ost/", 0), 0u
    );
}

TEST_F(PkiTest, an_mds_without_a_name_gets_an_id) {
    std::string ca = path("ca");
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), 0);
    std::string cert = path("mds.crt");
    std::string key = path("mds.key");
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_MDS, nullptr, nullptr, 3600, cert.c_str(),
            key.c_str(), identity, sizeof(identity), nullptr
        ),
        0
    );
    EXPECT_EQ(
        std::string(identity).rfind("spiffe://cluster.example/mds/", 0), 0u
    );
}

TEST_F(PkiTest, every_type_has_its_shape) {
    std::string ca = path("ca");
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), 0);
    std::string cert = path("x.crt");
    std::string key = path("x.key");
    const char* account = "0198f1a2-3b4c-7d5e-8f90-0123456789ab";
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_MDS, nullptr, mds_id, 3600, cert.c_str(),
            key.c_str(), identity, sizeof(identity), nullptr
        ),
        0
    );
    EXPECT_EQ(
        std::string(identity),
        std::string("spiffe://cluster.example/mds/") + mds_id
    );
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_ADMIN, nullptr, "ops", 3600, cert.c_str(),
            key.c_str(), identity, sizeof(identity), nullptr
        ),
        0
    );
    EXPECT_EQ(std::string(identity), "spiffe://cluster.example/admin/ops");
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_CLIENT, account, "vm-1", 3600, cert.c_str(),
            key.c_str(), identity, sizeof(identity), nullptr
        ),
        0
    );
    EXPECT_EQ(
        std::string(identity),
        std::string("spiffe://cluster.example/account/") + account +
            "/client/vm-1"
    );
}

TEST_F(PkiTest, failures_are_errno_and_a_message) {
    std::string ca = path("ca");
    std::string cert = path("x.crt");
    std::string key = path("x.key");
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, ost_id, 3600, cert.c_str(),
            key.c_str(), nullptr, 0, nullptr
        ),
        -ENOENT
    );
    EXPECT_NE(std::string(rawstor_pki_error()).find(ca), std::string::npos);

    EXPECT_EQ(rawstor_pki_init(ca.c_str(), "Not A Domain", 86400), -EINVAL);
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), 0);
    EXPECT_EQ(rawstor_pki_error()[0], '\0');
    EXPECT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), -EEXIST);

    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, "not an id", 3600,
            cert.c_str(), key.c_str(), nullptr, 0, nullptr
        ),
        -EINVAL
    );
    EXPECT_NE(
        std::string(rawstor_pki_error()).find("not an id"), std::string::npos
    );
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, ost_id, 0, cert.c_str(),
            key.c_str(), nullptr, 0, nullptr
        ),
        -EINVAL
    );
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_MDS, nullptr, "mds-1", 3600, cert.c_str(),
            key.c_str(), nullptr, 0, nullptr
        ),
        -EINVAL
    );
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_CLIENT, nullptr, "vm", 3600, cert.c_str(),
            key.c_str(), nullptr, 0, nullptr
        ),
        -EINVAL
    );
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), static_cast<RawstorPkiType>(99), nullptr, "x", 3600,
            cert.c_str(), key.c_str(), nullptr, 0, nullptr
        ),
        -EINVAL
    );
    // A buffer that is too small is refused before anything is issued.
    char small[8];
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, ost_id, 3600, cert.c_str(),
            key.c_str(), small, sizeof(small), nullptr
        ),
        -EINVAL
    );
    EXPECT_FALSE(fs::exists(cert));
    EXPECT_FALSE(fs::exists(key));
    EXPECT_EQ(
        rawstor_pki_renew(
            ca.c_str(), cert.c_str(), key.c_str(), 3600, nullptr, 0
        ),
        -ENOENT
    );
}

TEST_F(PkiTest, show_reads_a_certificate) {
    std::string ca = path("ca");
    std::string other = path("other");
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "cluster.example", 86400), 0);
    ASSERT_EQ(rawstor_pki_init(other.c_str(), "cluster.example", 86400), 0);
    std::string cert = path("ost.crt");
    std::string key = path("ost.key");
    ASSERT_EQ(
        rawstor_pki_issue(
            ca.c_str(), RAWSTOR_PKI_OST, nullptr, ost_id, 3600, cert.c_str(),
            key.c_str(), nullptr, 0, nullptr
        ),
        0
    );

    RawstorPkiInfo info;
    ASSERT_EQ(rawstor_pki_show(cert.c_str(), nullptr, &info), 0);
    EXPECT_EQ(
        std::string(info.identity),
        std::string("spiffe://cluster.example/ost/") + ost_id
    );
    EXPECT_EQ(info.issued, -1);
    EXPECT_GT(info.not_after, (long long)time(nullptr));
    EXPECT_LE(info.not_after, (long long)time(nullptr) + 3600 + 5);

    fs::remove(ca + "/ca.key");
    fs::remove(other + "/ca.key");
    ASSERT_EQ(rawstor_pki_show(cert.c_str(), ca.c_str(), &info), 0);
    EXPECT_EQ(info.issued, 1);
    ASSERT_EQ(rawstor_pki_show(cert.c_str(), other.c_str(), &info), 0);
    EXPECT_EQ(info.issued, 0);

    EXPECT_EQ(
        rawstor_pki_show(path("none.crt").c_str(), nullptr, &info), -ENOENT
    );
    EXPECT_EQ(
        rawstor_pki_show(cert.c_str(), path("nope").c_str(), &info), -ENOENT
    );
    std::string ca_crt = ca + "/ca.crt";
    EXPECT_EQ(rawstor_pki_show(ca_crt.c_str(), nullptr, &info), -EINVAL);
    EXPECT_NE(std::string(rawstor_pki_error()).find(ca_crt), std::string::npos);
}
