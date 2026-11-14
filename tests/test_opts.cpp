#include "opts.h"

#include <rawstor/rawstor.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <optional>
#include <string>

namespace {

class ScopedEnv {
    const char* _name;
    std::optional<std::string> _old;

public:
    ScopedEnv(const char* name, const char* value) : _name(name) {
        if (const char* old = getenv(name)) {
            _old = old;
        }
        setenv(name, value, 1);
    }
    ~ScopedEnv() {
        if (_old) {
            setenv(_name, _old->c_str(), 1);
        } else {
            unsetenv(_name);
        }
        rawstor_opts_initialize(nullptr);
    }
};

TEST(OptsTest, invalid_environment_fails_and_keeps_current_options) {
    unsigned int attempts = rawstor_opts_io_attempts();
    unsigned int jitter = rawstor_opts_io_retry_backoff_jitter();
    struct Case {
        const char* name;
        const char* value;
    };
    for (Case c : {
             Case{"RAWSTOR_OPTS_IO_ATTEMPTS", "0"},
             Case{"RAWSTOR_OPTS_IO_ATTEMPTS", "ten"},
             Case{"RAWSTOR_OPTS_LIST_LIMIT", ""},
             Case{"RAWSTOR_OPTS_IO_RETRY_BACKOFF_JITTER", "101"},
             Case{"RAWSTOR_OPTS_IO_RETRY_BACKOFF_MAX", "4294968"},
             Case{"RAWSTOR_OPTS_TCP_USER_TIMEOUT", "2147483648"},
             Case{"RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL", "0"},
             Case{"RAWSTOR_OPTS_WRITE_BACKLOG_CAPACITY", "256X"},
         }) {
        ScopedEnv env(c.name, c.value);
        EXPECT_EQ(rawstor_opts_initialize(nullptr), -EINVAL)
            << c.name << "=" << c.value;
        EXPECT_EQ(rawstor_opts_io_attempts(), attempts);
        EXPECT_EQ(rawstor_opts_io_retry_backoff_jitter(), jitter);
    }
}

TEST(OptsTest, zero_disables_timeouts) {
    ScopedEnv env("RAWSTOR_OPTS_SO_RCVTIMEO", "0");
    EXPECT_EQ(rawstor_opts_initialize(nullptr), 0);
    EXPECT_EQ(rawstor_opts_so_rcvtimeo(), 0u);
}

TEST(OptsTest, tls_settings_come_together_or_not_at_all) {
    EXPECT_EQ(rawstor_opts_tls_trust_domain(), nullptr);
    {
        ScopedEnv cert("RAWSTOR_TLS_CERT", "/etc/rawstor/tls/cert.pem");
        EXPECT_EQ(rawstor_opts_initialize(nullptr), -EINVAL);
    }
    {
        ScopedEnv domain("RAWSTOR_TLS_TRUST_DOMAIN", "cluster.example");
        ScopedEnv cert("RAWSTOR_TLS_CERT", "/etc/rawstor/tls/cert.pem");
        ScopedEnv key("RAWSTOR_TLS_KEY", "/etc/rawstor/tls/key.pem");
        EXPECT_EQ(rawstor_opts_initialize(nullptr), -EINVAL);
    }
    {
        ScopedEnv domain("RAWSTOR_TLS_TRUST_DOMAIN", "");
        EXPECT_EQ(rawstor_opts_initialize(nullptr), -EINVAL);
    }
}

TEST(OptsTest, tls_extras_need_the_tls_settings) {
    {
        ScopedEnv mds("RAWSTOR_TLS_MDS_ID", "mds-1");
        EXPECT_EQ(rawstor_opts_initialize(nullptr), -EINVAL);
    }
    {
        ScopedEnv crl("RAWSTOR_TLS_CRL", "/etc/rawstor/tls/ca.crl");
        EXPECT_EQ(rawstor_opts_initialize(nullptr), -EINVAL);
    }
}

TEST(OptsTest, tls_settings_are_read) {
    {
        ScopedEnv domain("RAWSTOR_TLS_TRUST_DOMAIN", "cluster.example");
        ScopedEnv cert("RAWSTOR_TLS_CERT", "/etc/rawstor/tls/cert.pem");
        ScopedEnv key("RAWSTOR_TLS_KEY", "/etc/rawstor/tls/key.pem");
        ScopedEnv ca("RAWSTOR_TLS_CA", "/etc/rawstor/tls/ca.pem");
        ScopedEnv crl("RAWSTOR_TLS_CRL", "/etc/rawstor/tls/ca.crl");
        ScopedEnv mds("RAWSTOR_TLS_MDS_ID", "mds-1");
        EXPECT_EQ(rawstor_opts_initialize(nullptr), 0);
        EXPECT_STREQ(rawstor_opts_tls_trust_domain(), "cluster.example");
        EXPECT_STREQ(rawstor_opts_tls_cert(), "/etc/rawstor/tls/cert.pem");
        EXPECT_STREQ(rawstor_opts_tls_key(), "/etc/rawstor/tls/key.pem");
        EXPECT_STREQ(rawstor_opts_tls_ca(), "/etc/rawstor/tls/ca.pem");
        EXPECT_STREQ(rawstor_opts_tls_crl(), "/etc/rawstor/tls/ca.crl");
        EXPECT_STREQ(rawstor_opts_tls_mds_id(), "mds-1");
    }
    EXPECT_EQ(rawstor_opts_tls_trust_domain(), nullptr);
    EXPECT_EQ(rawstor_opts_tls_mds_id(), nullptr);
}

TEST(OptsTest, invalid_struct_values_fail) {
    RawstorOpts opts{};
    opts.io_retry_backoff_jitter = 101;
    EXPECT_EQ(rawstor_opts_initialize(&opts), -EINVAL);
    opts.io_retry_backoff_jitter = 100;
    EXPECT_EQ(rawstor_opts_initialize(&opts), 0);
    EXPECT_EQ(rawstor_opts_io_retry_backoff_jitter(), 100u);
    rawstor_opts_initialize(nullptr);
}

} // namespace
