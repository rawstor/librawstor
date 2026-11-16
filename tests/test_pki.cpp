#include <rawstor/pki.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <filesystem>
#include <string>
#include <system_error>

#include <stdlib.h>

namespace {

namespace fs = std::filesystem;

const char* const ost_id =
    "spiffe://cluster.example/ost/0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";

class PkiTest : public ::testing::Test {
protected:
    fs::path dir;

    void SetUp() override {
        std::string pattern =
            (fs::temp_directory_path() / "rawstor-pki-XXXXXX").string();
        ASSERT_NE(mkdtemp(pattern.data()), nullptr);
        dir = pattern;
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
    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "test CA", 86400), 0);
    EXPECT_TRUE(fs::exists(ca + "/ca.crt"));
    EXPECT_TRUE(fs::exists(ca + "/ca.key"));

    std::string cert = path("ost.crt");
    std::string key = path("ost.key");
    ASSERT_EQ(
        rawstor_pki_issue(ca.c_str(), ost_id, 3600, cert.c_str(), key.c_str()),
        0
    );
    EXPECT_TRUE(fs::exists(cert));
    EXPECT_TRUE(fs::exists(key));

    auto before = fs::file_size(cert);
    ASSERT_EQ(
        rawstor_pki_renew(ca.c_str(), cert.c_str(), key.c_str(), 3600), 0
    );
    EXPECT_EQ(fs::file_size(cert), before);
}

TEST_F(PkiTest, failures_are_errno_and_a_message) {
    std::string ca = path("ca");
    EXPECT_EQ(
        rawstor_pki_issue(ca.c_str(), ost_id, 3600, "c.crt", "c.key"), -ENOENT
    );
    EXPECT_NE(std::string(rawstor_pki_error()).find(ca), std::string::npos);

    ASSERT_EQ(rawstor_pki_init(ca.c_str(), "test CA", 86400), 0);
    EXPECT_EQ(rawstor_pki_error()[0], '\0');
    EXPECT_EQ(rawstor_pki_init(ca.c_str(), "test CA", 86400), -EEXIST);

    std::string cert = path("x.crt");
    std::string key = path("x.key");
    EXPECT_EQ(
        rawstor_pki_issue(
            ca.c_str(), "not an id", 3600, cert.c_str(), key.c_str()
        ),
        -EINVAL
    );
    EXPECT_NE(
        std::string(rawstor_pki_error()).find("not an id"), std::string::npos
    );
    EXPECT_EQ(
        rawstor_pki_issue(ca.c_str(), ost_id, 0, cert.c_str(), key.c_str()),
        -EINVAL
    );
    EXPECT_FALSE(fs::exists(cert));
    EXPECT_EQ(
        rawstor_pki_renew(ca.c_str(), cert.c_str(), key.c_str(), 3600), -ENOENT
    );
}
