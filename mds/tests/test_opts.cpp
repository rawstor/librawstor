#include <mds/opts.hpp>

#include <gtest/gtest.h>

#include <cstdlib>
#include <optional>
#include <string>
#include <system_error>

namespace {

class ScopedEnv {
    const char* _name;
    std::optional<std::string> _old;

public:
    ScopedEnv(const char* name, const char* value) : _name(name) {
        if (const char* old = getenv(name)) {
            _old = old;
        }
        if (value) {
            setenv(name, value, 1);
        } else {
            unsetenv(name);
        }
    }
    ~ScopedEnv() {
        if (_old) {
            setenv(_name, _old->c_str(), 1);
        } else {
            unsetenv(_name);
        }
    }
};

TEST(MdsOptsTest, defaults_and_overrides) {
    ScopedEnv interval("RAWSTOR_MDS_OPTS_INFO_INTERVAL", nullptr);
    ScopedEnv concurrency("RAWSTOR_MDS_OPTS_INFO_CONCURRENCY", nullptr);
    auto defaults = rawstor::mdsserver::Opts::from_env();
    EXPECT_EQ(defaults.info_interval, 300000u);
    EXPECT_EQ(defaults.info_concurrency, 128u);
    setenv("RAWSTOR_MDS_OPTS_INFO_INTERVAL", "2500", 1);
    setenv("RAWSTOR_MDS_OPTS_INFO_CONCURRENCY", "32", 1);
    auto overridden = rawstor::mdsserver::Opts::from_env();
    EXPECT_EQ(overridden.info_interval, 2500u);
    EXPECT_EQ(overridden.info_concurrency, 32u);
    setenv("RAWSTOR_MDS_OPTS_INFO_CONCURRENCY", "1024", 1);
    EXPECT_EQ(rawstor::mdsserver::Opts::from_env().info_concurrency, 1024u);
}

TEST(MdsOptsTest, invalid_values_are_configuration_errors) {
    ScopedEnv interval("RAWSTOR_MDS_OPTS_INFO_INTERVAL", nullptr);
    ScopedEnv concurrency("RAWSTOR_MDS_OPTS_INFO_CONCURRENCY", nullptr);
    for (const char* bad : {"0", "", "5m", "-1"}) {
        setenv("RAWSTOR_MDS_OPTS_INFO_INTERVAL", bad, 1);
        EXPECT_THROW(rawstor::mdsserver::Opts::from_env(), std::system_error)
            << bad;
    }
    unsetenv("RAWSTOR_MDS_OPTS_INFO_INTERVAL");
    for (const char* bad : {"0", "1025", "abc"}) {
        setenv("RAWSTOR_MDS_OPTS_INFO_CONCURRENCY", bad, 1);
        EXPECT_THROW(rawstor::mdsserver::Opts::from_env(), std::system_error)
            << bad;
    }
}

} // namespace
