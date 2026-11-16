#include <gtest/gtest.h>

#include <rawtls/ca.hpp>
#include <rawtls/context.hpp>

#include "pki.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <system_error>

#include <sys/stat.h>

namespace {

namespace fs = std::filesystem;

const std::string ost_uri =
    "spiffe://cluster.example/ost/0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";
const std::chrono::seconds hour(3600);

class Dir final {
private:
    fs::path _path;

public:
    Dir() {
        std::string pattern =
            (fs::temp_directory_path() / "rawtls-ca-XXXXXX").string();
        EXPECT_NE(mkdtemp(pattern.data()), nullptr);
        _path = pattern;
    }

    ~Dir() {
        std::error_code ignored;
        fs::remove_all(_path, ignored);
    }

    std::string path(const std::string& name = "") const {
        return name.empty() ? _path.string() : (_path / name).string();
    }
};

mode_t mode_of(const std::string& file) {
    struct stat st;
    EXPECT_EQ(stat(file.c_str(), &st), 0) << file;
    return st.st_mode & 07777;
}

std::unique_ptr<X509, void (*)(X509*)> load(const std::string& file) {
    FILE* f = fopen(file.c_str(), "r");
    EXPECT_NE(f, nullptr) << file;
    std::unique_ptr<X509, void (*)(X509*)> cert(
        PEM_read_X509(f, nullptr, nullptr, nullptr), X509_free
    );
    fclose(f);
    return cert;
}

std::string serial_of(const std::string& file) {
    auto cert = load(file);
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> bn(
        ASN1_INTEGER_to_BN(X509_get0_serialNumber(cert.get()), nullptr), BN_free
    );
    char* hex = BN_bn2hex(bn.get());
    std::string s = hex;
    OPENSSL_free(hex);
    return s;
}

void expect_errno(int expected, const std::function<void()>& call) {
    try {
        call();
        FAIL() << "no error, expected " << expected;
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), expected) << e.what();
    }
}

} // namespace

TEST(CaTest, init_makes_a_ca_whose_key_is_private) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);

    EXPECT_EQ(mode_of(dir.path("ca")), 0700u);
    EXPECT_EQ(mode_of(dir.path("ca/ca.key")), 0600u);
    EXPECT_EQ(mode_of(dir.path("ca/ca.crt")), 0644u);
    EXPECT_FALSE(fs::exists(dir.path("ca/ca.key.tmp")));

    auto cert = load(dir.path("ca/ca.crt"));
    EXPECT_EQ(X509_check_ca(cert.get()), 1);
    EXPECT_EQ(X509_self_signed(cert.get(), 1), 1);
}

TEST(CaTest, init_refuses_an_existing_ca) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);
    std::string before = serial_of(dir.path("ca/ca.crt"));
    expect_errno(EEXIST, [&] {
        rawtls::Ca::init(dir.path("ca"), "other CA", hour);
    });
    EXPECT_EQ(serial_of(dir.path("ca/ca.crt")), before);
}

TEST(CaTest, init_rejects_bad_arguments) {
    Dir dir;
    expect_errno(EINVAL, [&] { rawtls::Ca::init(dir.path("a"), "", hour); });
    expect_errno(EINVAL, [&] {
        rawtls::Ca::init(dir.path("b"), "CA", std::chrono::seconds(0));
    });
}

TEST(CaTest, a_missing_ca_is_not_opened) {
    Dir dir;
    expect_errno(ENOENT, [&] { rawtls::Ca ca(dir.path("nothing")); });
}

TEST(CaTest, issues_a_certificate_a_context_takes) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);
    rawtls::Ca ca(dir.path("ca"));
    ca.issue(ost_uri, hour, dir.path("ost.crt"), dir.path("ost.key"));

    EXPECT_EQ(mode_of(dir.path("ost.key")), 0600u);

    auto cert = load(dir.path("ost.crt"));
    auto root = load(ca.ca_file());
    EXPECT_EQ(X509_check_issued(root.get(), cert.get()), X509_V_OK);
    EXPECT_EQ(X509_check_ca(cert.get()), 0);

    // Exactly one URI SAN, and it is the identity.
    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)
    );
    ASSERT_NE(names, nullptr);
    ASSERT_EQ(sk_GENERAL_NAME_num(names), 1);
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, 0);
    ASSERT_EQ(name->type, GEN_URI);
    EXPECT_EQ(
        std::string(
            reinterpret_cast<const char*>(
                ASN1_STRING_get0_data(name->d.uniformResourceIdentifier)
            ),
            static_cast<size_t>(
                ASN1_STRING_length(name->d.uniformResourceIdentifier)
            )
        ),
        ost_uri
    );
    GENERAL_NAMES_free(names);

    uint32_t xku = X509_get_extended_key_usage(cert.get());
    EXPECT_TRUE(xku & XKU_SSL_SERVER);
    EXPECT_TRUE(xku & XKU_SSL_CLIENT);

    rawtls::Config config;
    config.trust_domain = "cluster.example";
    config.cert_file = dir.path("ost.crt");
    config.key_file = dir.path("ost.key");
    config.ca_file = ca.ca_file();
    EXPECT_NO_THROW(rawtls::Context context(config));
}

TEST(CaTest, issue_checks_the_identity) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);
    rawtls::Ca ca(dir.path("ca"));
    for (const char* bad :
         {"", "ost", "https://cluster.example/ost/x",
          "spiffe://cluster.example/ost/not-a-uuid",
          "spiffe://cluster.example/nobody/x"}) {
        expect_errno(EINVAL, [&] {
            ca.issue(bad, hour, dir.path("x.crt"), dir.path("x.key"));
        });
    }
    EXPECT_FALSE(fs::exists(dir.path("x.crt")));
    EXPECT_FALSE(fs::exists(dir.path("x.key")));
    expect_errno(EINVAL, [&] {
        ca.issue(
            ost_uri, std::chrono::seconds(-1), dir.path("x.crt"),
            dir.path("x.key")
        );
    });
}

TEST(CaTest, renew_keeps_the_identity_and_changes_the_rest) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);
    rawtls::Ca ca(dir.path("ca"));
    ca.issue(ost_uri, hour, dir.path("ost.crt"), dir.path("ost.key"));
    std::string serial = serial_of(dir.path("ost.crt"));

    ca.renew(dir.path("ost.crt"), dir.path("ost.key"), 2 * hour);

    EXPECT_NE(serial_of(dir.path("ost.crt")), serial);
    EXPECT_EQ(mode_of(dir.path("ost.key")), 0600u);
    rawtls::Config config;
    config.trust_domain = "cluster.example";
    config.cert_file = dir.path("ost.crt");
    config.key_file = dir.path("ost.key");
    config.ca_file = ca.ca_file();
    EXPECT_NO_THROW(rawtls::Context context(config));
}

TEST(CaTest, renew_refuses_what_another_ca_issued) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);
    rawtls::Ca ca(dir.path("ca"));

    rawtls::testing::Pki other;
    rawtls::testing::IssueOptions options;
    options.uris = {ost_uri};
    rawtls::testing::Identity foreign = other.issue("foreign", options);

    expect_errno(EINVAL, [&] {
        ca.renew(foreign.cert_file, foreign.key_file, hour);
    });
}

TEST(CaTest, renew_needs_an_existing_certificate) {
    Dir dir;
    rawtls::Ca::init(dir.path("ca"), "test CA", hour);
    rawtls::Ca ca(dir.path("ca"));
    expect_errno(ENOENT, [&] {
        ca.renew(dir.path("none.crt"), dir.path("none.key"), hour);
    });
}
