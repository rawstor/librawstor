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
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <string>
#include <system_error>

#include <sys/stat.h>

namespace {

namespace fs = std::filesystem;

const std::string ost_id = "0198f1a2-3b4c-7d5e-8f90-a1b2c3d4e5f6";
const std::string ost_uri = "spiffe://cluster.example/ost/" + ost_id;
const std::string mds_id = "0198f1a2-3b4c-7d5e-8f90-fedcba987654";
const std::string account = "0198f1a2-3b4c-7d5e-8f90-0123456789ab";
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

std::string read_file(const std::string& file) {
    std::ifstream in(file, std::ios::binary);
    return std::string(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()
    );
}

void expect_errno(int expected, const std::function<void()>& call) {
    try {
        call();
        FAIL() << "no error, expected " << expected;
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), expected) << e.what();
    }
}

std::string uri_of(const std::string& file) {
    auto cert = load(file);
    GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert.get(), NID_subject_alt_name, nullptr, nullptr)
    );
    EXPECT_NE(names, nullptr);
    EXPECT_EQ(sk_GENERAL_NAME_num(names), 1);
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, 0);
    EXPECT_EQ(name->type, GEN_URI);
    std::string uri(
        reinterpret_cast<const char*>(
            ASN1_STRING_get0_data(name->d.uniformResourceIdentifier)
        ),
        static_cast<size_t>(
            ASN1_STRING_length(name->d.uniformResourceIdentifier)
        )
    );
    GENERAL_NAMES_free(names);
    return uri;
}

// A CA in a directory of its own.
class CATest : public ::testing::Test {
protected:
    Dir dir;

    void init() { rawtls::CA::init(dir.path("ca"), "cluster.example", hour); }

    rawtls::Config config(const std::string& name) {
        rawtls::Config c;
        c.trust_domain = "cluster.example";
        c.cert_file = dir.path(name + ".crt");
        c.key_file = dir.path(name + ".key");
        c.ca_file = dir.path("ca/ca.crt");
        return c;
    }
};

} // namespace

TEST_F(CATest, init_makes_a_ca_whose_key_is_private) {
    init();

    EXPECT_EQ(mode_of(dir.path("ca")), 0700u);
    EXPECT_EQ(mode_of(dir.path("ca/ca.key")), 0600u);
    EXPECT_EQ(mode_of(dir.path("ca/ca.crt")), 0644u);
    // Nothing is left of the files written aside.
    size_t files = 0;
    for ([[maybe_unused]] const auto& entry :
         fs::directory_iterator(dir.path("ca"))) {
        ++files;
    }
    EXPECT_EQ(files, 2u);

    auto cert = load(dir.path("ca/ca.crt"));
    EXPECT_EQ(X509_check_ca(cert.get()), 1);
    EXPECT_EQ(X509_self_signed(cert.get(), 1), 1);
    EXPECT_EQ(rawtls::CA(dir.path("ca")).trust_domain(), "cluster.example");
}

TEST_F(CATest, init_refuses_an_existing_ca) {
    init();
    std::string before = serial_of(dir.path("ca/ca.crt"));
    expect_errno(EEXIST, [&] {
        rawtls::CA::init(dir.path("ca"), "other.example", hour);
    });
    EXPECT_EQ(serial_of(dir.path("ca/ca.crt")), before);
    EXPECT_EQ(rawtls::CA(dir.path("ca")).trust_domain(), "cluster.example");
}

TEST_F(CATest, init_rejects_bad_arguments) {
    for (const char* bad : {"", "Cluster.Example", "a/b", "cluster example"}) {
        expect_errno(EINVAL, [&] {
            rawtls::CA::init(dir.path("a"), bad, hour);
        });
    }
    expect_errno(EINVAL, [&] {
        rawtls::CA::init(
            dir.path("b"), "cluster.example", std::chrono::seconds(0)
        );
    });
}

TEST_F(CATest, a_missing_ca_is_not_opened) {
    expect_errno(ENOENT, [&] { rawtls::CA ca(dir.path("nothing")); });
}

TEST_F(CATest, an_ost_gets_a_certificate_a_context_takes) {
    init();
    rawtls::CA ca(dir.path("ca"));
    EXPECT_EQ(
        ca.issue(
            rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
            dir.path("ost.key")
        ),
        ost_uri
    );

    EXPECT_EQ(mode_of(dir.path("ost.key")), 0600u);
    EXPECT_EQ(mode_of(dir.path("ost.crt")), 0644u);

    auto cert = load(dir.path("ost.crt"));
    auto root = load(ca.ca_file());
    EXPECT_EQ(X509_check_issued(root.get(), cert.get()), X509_V_OK);
    EXPECT_EQ(X509_check_ca(cert.get()), 0);
    EXPECT_EQ(uri_of(dir.path("ost.crt")), ost_uri);

    uint32_t xku = X509_get_extended_key_usage(cert.get());
    EXPECT_TRUE(xku & XKU_SSL_SERVER);
    EXPECT_TRUE(xku & XKU_SSL_CLIENT);

    EXPECT_NO_THROW(rawtls::Context context(config("ost")));
}

TEST_F(CATest, an_ost_or_an_mds_without_an_id_gets_a_new_one) {
    init();
    rawtls::CA ca(dir.path("ca"));
    std::string first = ca.issue(
        rawtls::Type::ost, "", "", hour, dir.path("a.crt"), dir.path("a.key")
    );
    std::string second = ca.issue(
        rawtls::Type::ost, "", "", hour, dir.path("b.crt"), dir.path("b.key")
    );
    EXPECT_NE(first, second);
    EXPECT_EQ(rawtls::SpiffeId(first).type(), rawtls::Type::ost);
    EXPECT_EQ(uri_of(dir.path("a.crt")), first);

    std::string mds = ca.issue(
        rawtls::Type::mds, "", "", hour, dir.path("m.crt"), dir.path("m.key")
    );
    EXPECT_EQ(rawtls::SpiffeId(mds).type(), rawtls::Type::mds);
    EXPECT_EQ(uri_of(dir.path("m.crt")), mds);
}

TEST_F(CATest, every_type_gets_its_shape) {
    init();
    rawtls::CA ca(dir.path("ca"));
    EXPECT_EQ(
        ca.issue(
            rawtls::Type::mds, "", mds_id, hour, dir.path("m.crt"),
            dir.path("m.key")
        ),
        "spiffe://cluster.example/mds/" + mds_id
    );
    EXPECT_EQ(
        ca.issue(
            rawtls::Type::admin, "", "ops", hour, dir.path("a.crt"),
            dir.path("a.key")
        ),
        "spiffe://cluster.example/admin/ops"
    );
    EXPECT_EQ(
        ca.issue(
            rawtls::Type::client, account, "vm-1", hour, dir.path("c.crt"),
            dir.path("c.key")
        ),
        "spiffe://cluster.example/account/" + account + "/client/vm-1"
    );
    for (const char* name : {"m", "a", "c"}) {
        EXPECT_NO_THROW(rawtls::Context context(config(name)));
    }
}

TEST_F(CATest, issue_checks_what_it_is_asked) {
    init();
    rawtls::CA ca(dir.path("ca"));
    auto issue = [&](rawtls::Type type, const std::string& t,
                     const std::string& name) {
        return [&, type, t, name] {
            ca.issue(type, t, name, hour, dir.path("x.crt"), dir.path("x.key"));
        };
    };
    expect_errno(EINVAL, issue(rawtls::Type::ost, "", "not-a-uuid"));
    expect_errno(EINVAL, issue(rawtls::Type::mds, "", "mds-1"));
    expect_errno(EINVAL, issue(rawtls::Type::mds, "", "a/b"));
    expect_errno(EINVAL, issue(rawtls::Type::admin, "", ""));
    expect_errno(EINVAL, issue(rawtls::Type::admin, account, "ops"));
    expect_errno(EINVAL, issue(rawtls::Type::client, "", "vm"));
    expect_errno(EINVAL, issue(rawtls::Type::client, account, ""));
    expect_errno(EINVAL, issue(rawtls::Type::client, "not-a-uuid", "vm"));
    EXPECT_FALSE(fs::exists(dir.path("x.crt")));
    EXPECT_FALSE(fs::exists(dir.path("x.key")));
    expect_errno(EINVAL, [&] {
        ca.issue(
            rawtls::Type::ost, "", ost_id, std::chrono::seconds(-1),
            dir.path("x.crt"), dir.path("x.key")
        );
    });
}

TEST_F(CATest, renew_keeps_the_identity_and_changes_the_rest) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    std::string serial = serial_of(dir.path("ost.crt"));

    EXPECT_EQ(
        ca.renew(dir.path("ost.crt"), dir.path("ost.key"), 2 * hour), ost_uri
    );

    EXPECT_NE(serial_of(dir.path("ost.crt")), serial);
    EXPECT_EQ(uri_of(dir.path("ost.crt")), ost_uri);
    EXPECT_EQ(mode_of(dir.path("ost.key")), 0600u);
    EXPECT_NO_THROW(rawtls::Context context(config("ost")));
}

TEST_F(CATest, renew_refuses_what_another_ca_issued) {
    init();
    rawtls::CA ca(dir.path("ca"));

    rawtls::testing::Pki other;
    rawtls::testing::IssueOptions options;
    options.uris = {ost_uri};
    rawtls::testing::Identity foreign = other.issue("foreign", options);

    expect_errno(EINVAL, [&] {
        ca.renew(foreign.cert_file, foreign.key_file, hour);
    });
}

TEST_F(CATest, renew_needs_an_existing_certificate) {
    init();
    rawtls::CA ca(dir.path("ca"));
    expect_errno(ENOENT, [&] {
        ca.renew(dir.path("none.crt"), dir.path("none.key"), hour);
    });
}

// A file or a symlink that somebody put where a temporary file would go is not
// written through: the key of the CA must not end up in a file of theirs.
TEST_F(CATest, a_planted_symlink_is_not_followed) {
    fs::create_directories(dir.path("ca"));
    std::string victim = dir.path("victim");
    {
        FILE* f = fopen(victim.c_str(), "w");
        ASSERT_NE(f, nullptr);
        fputs("precious", f);
        fclose(f);
    }
    for (const char* name :
         {"ca.key.tmp", "ca.crt.tmp", ".ca.key.tmp", ".ca.key.XXXXXX"}) {
        fs::create_symlink(victim, dir.path(std::string("ca/") + name));
    }
    init();

    FILE* f = fopen(victim.c_str(), "r");
    ASSERT_NE(f, nullptr);
    char buffer[16] = {};
    EXPECT_EQ(fread(buffer, 1, sizeof(buffer) - 1, f), 8u);
    fclose(f);
    EXPECT_EQ(std::string(buffer), "precious");

    // And an output that is itself a symlink is replaced, not written through.
    fs::create_symlink(victim, dir.path("ost.key"));
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    EXPECT_FALSE(fs::is_symlink(dir.path("ost.key")));
    f = fopen(victim.c_str(), "r");
    ASSERT_NE(f, nullptr);
    memset(buffer, 0, sizeof(buffer));
    EXPECT_EQ(fread(buffer, 1, sizeof(buffer) - 1, f), 8u);
    fclose(f);
    EXPECT_EQ(std::string(buffer), "precious");
}

// A certificate that cannot be written leaves the key it was issued with out
// too: the pair that was there stays.
TEST_F(CATest, a_failed_write_leaves_the_old_pair) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    std::string key = read_file(dir.path("ost.key"));
    std::string cert = read_file(dir.path("ost.crt"));

    // The certificate goes where nothing can be written.
    expect_errno(ENOENT, [&] {
        ca.issue(
            rawtls::Type::ost, "", ost_id, hour, dir.path("nowhere/ost.crt"),
            dir.path("ost.key")
        );
    });

    EXPECT_EQ(read_file(dir.path("ost.key")), key);
    EXPECT_EQ(read_file(dir.path("ost.crt")), cert);
}

TEST_F(CATest, inspect_reads_what_a_certificate_says) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );

    rawtls::CertInfo info = rawtls::inspect(dir.path("ost.crt"));
    EXPECT_EQ(info.identity, ost_uri);
    long long now = time(nullptr);
    EXPECT_GT(info.not_after, now);
    EXPECT_LE(info.not_after, now + 3600 + 5);
}

TEST_F(CATest, inspect_refuses_what_names_no_process) {
    init();
    expect_errno(ENOENT, [&] { rawtls::inspect(dir.path("none.crt")); });
    // The CA's own certificate has no URI SAN.
    expect_errno(EINVAL, [&] { rawtls::inspect(dir.path("ca/ca.crt")); });

    // A SAN that is not an identity of rawstor.
    rawtls::testing::Pki other;
    rawtls::testing::IssueOptions options;
    options.uris = {"spiffe://cluster.example/nobody/x"};
    rawtls::testing::Identity foreign = other.issue("foreign", options);
    expect_errno(EINVAL, [&] { rawtls::inspect(foreign.cert_file); });
}

TEST_F(CATest, issued_tells_whose_certificate_it_is) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    EXPECT_TRUE(ca.issued(dir.path("ost.crt")));

    rawtls::CA::init(dir.path("other"), "cluster.example", hour);
    EXPECT_FALSE(rawtls::CA(dir.path("other")).issued(dir.path("ost.crt")));

    rawtls::testing::Pki foreign_pki;
    rawtls::testing::IssueOptions options;
    options.uris = {ost_uri};
    EXPECT_FALSE(ca.issued(foreign_pki.issue("foreign", options).cert_file));
    expect_errno(ENOENT, [&] { ca.issued(dir.path("none.crt")); });
}

TEST_F(CATest, a_failed_certificate_publish_restores_the_old_key) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    std::string key = read_file(dir.path("ost.key"));
    std::string cert = read_file(dir.path("ost.crt"));
    fs::create_directory(dir.path("blocked.crt"));
    EXPECT_THROW(
        ca.issue(
            rawtls::Type::ost, "", ost_id, hour, dir.path("blocked.crt"),
            dir.path("ost.key")
        ),
        std::system_error
    );
    EXPECT_EQ(read_file(dir.path("ost.key")), key);
    EXPECT_EQ(read_file(dir.path("ost.crt")), cert);
    EXPECT_NO_THROW(rawtls::Context context(config("ost")));
}

TEST_F(CATest, a_failed_certificate_publish_removes_a_new_key) {
    init();
    rawtls::CA ca(dir.path("ca"));
    fs::create_directory(dir.path("blocked.crt"));
    EXPECT_THROW(
        ca.issue(
            rawtls::Type::ost, "", ost_id, hour, dir.path("blocked.crt"),
            dir.path("new.key")
        ),
        std::system_error
    );
    EXPECT_FALSE(fs::exists(dir.path("new.key")));
}

TEST_F(CATest, a_failed_certificate_publish_restores_a_key_symlink) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("original.key")
    );
    std::string key = read_file(dir.path("original.key"));
    fs::create_symlink(dir.path("original.key"), dir.path("ost.key"));
    fs::create_directory(dir.path("blocked.crt"));
    EXPECT_THROW(
        ca.issue(
            rawtls::Type::ost, "", ost_id, hour, dir.path("blocked.crt"),
            dir.path("ost.key")
        ),
        std::system_error
    );
    EXPECT_TRUE(fs::is_symlink(dir.path("ost.key")));
    EXPECT_EQ(read_file(dir.path("original.key")), key);
    EXPECT_NO_THROW(rawtls::Context context(config("ost")));
    for (const auto& entry : fs::directory_iterator(dir.path())) {
        EXPECT_NE(entry.path().filename().string().front(), '.');
    }
}

TEST_F(CATest, verification_needs_only_the_ca_certificate) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    fs::remove(dir.path("ca/ca.key"));

    rawtls::CA verifier(dir.path("ca"));
    EXPECT_TRUE(verifier.issued(dir.path("ost.crt")));
    rawtls::CertInfo info =
        rawtls::inspect(dir.path("ost.crt"), verifier.ca_file());
    EXPECT_EQ(info.identity, ost_uri);
    EXPECT_EQ(info.issued, 1);
    EXPECT_EQ(rawtls::inspect(dir.path("ost.crt")).issued, -1);

    rawtls::testing::Pki other;
    rawtls::testing::IssueOptions options;
    options.uris = {ost_uri};
    auto foreign = other.issue("foreign", options);
    EXPECT_FALSE(verifier.issued(foreign.cert_file));
    EXPECT_EQ(rawtls::inspect(foreign.cert_file, verifier.ca_file()).issued, 0);
    expect_errno(ENOENT, [&] {
        verifier.renew(dir.path("ost.crt"), dir.path("ost.key"), hour);
    });
}

TEST_F(CATest, a_forged_identity_is_not_renewed_or_reported_as_issued) {
    init();
    rawtls::CA ca(dir.path("ca"));
    ca.issue(
        rawtls::Type::ost, "", ost_id, hour, dir.path("ost.crt"),
        dir.path("ost.key")
    );
    auto cert = load(dir.path("ost.crt"));
    int index = X509_get_ext_by_NID(cert.get(), NID_subject_alt_name, -1);
    ASSERT_GE(index, 0);
    X509_EXTENSION_free(X509_delete_ext(cert.get(), index));
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_subject_alt_name,
        "URI:spiffe://cluster.example/admin/forged"
    );
    ASSERT_NE(ext, nullptr);
    ASSERT_EQ(X509_add_ext(cert.get(), ext, -1), 1);
    X509_EXTENSION_free(ext);
    // Refresh the encoded body without signing it: the signature must still
    // be that of the original OST identity.
    ASSERT_GT(i2d_re_X509_tbs(cert.get(), nullptr), 0);
    FILE* f = fopen(dir.path("forged.crt").c_str(), "w");
    ASSERT_NE(f, nullptr);
    ASSERT_EQ(PEM_write_X509(f, cert.get()), 1);
    ASSERT_EQ(fclose(f), 0);

    rawtls::CertInfo info =
        rawtls::inspect(dir.path("forged.crt"), ca.ca_file());
    EXPECT_EQ(info.identity, "spiffe://cluster.example/admin/forged");
    EXPECT_EQ(info.issued, 0);
    std::string key = read_file(dir.path("ost.key"));
    expect_errno(EINVAL, [&] {
        ca.renew(dir.path("forged.crt"), dir.path("ost.key"), hour);
    });
    EXPECT_EQ(read_file(dir.path("ost.key")), key);
}
