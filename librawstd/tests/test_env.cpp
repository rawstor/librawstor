#include <rawstd/env.h>
#include <rawstd/logging.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <limits>
#include <optional>
#include <string>

namespace {

const char* const env_name = "RAWSTD_TEST_ENV_VALUE";

class EnvTest : public testing::Test {
    std::optional<std::string> _old;

protected:
    // Invalid values are logged.
    static void SetUpTestSuite() { ASSERT_EQ(rawstd_logging_initialize(), 0); }
    static void TearDownTestSuite() { rawstd_logging_terminate(); }

    void SetUp() override {
        if (const char* old = getenv(env_name)) {
            _old = old;
        }
        unsetenv(env_name);
    }
    void TearDown() override {
        if (_old) {
            setenv(env_name, _old->c_str(), 1);
        } else {
            unsetenv(env_name);
        }
    }
};

TEST_F(EnvTest, uint_defaults_and_bounds) {
    unsigned int out = 7;
    EXPECT_EQ(rawstd_env_uint(env_name, 42, 0, UINT_MAX, &out), 0);
    EXPECT_EQ(out, 42u);

    setenv(env_name, "0", 1);
    EXPECT_EQ(rawstd_env_uint(env_name, 42, 0, UINT_MAX, &out), 0);
    EXPECT_EQ(out, 0u);
    auto max = std::to_string(UINT_MAX);
    setenv(env_name, max.c_str(), 1);
    EXPECT_EQ(rawstd_env_uint(env_name, 42, 0, UINT_MAX, &out), 0);
    EXPECT_EQ(out, UINT_MAX);
    setenv(env_name, "10", 1);
    EXPECT_EQ(rawstd_env_uint(env_name, 42, 10, 10, &out), 0);
    EXPECT_EQ(out, 10u);
}

TEST_F(EnvTest, uint_rejects_malformed_and_out_of_range_values) {
    for (const char* bad :
         {"", " 1", "1 ", "+1", "-1", "10junk", "0x10", "1.5", "4294967296",
          "999999999999999999999999999999"}) {
        setenv(env_name, bad, 1);
        unsigned int out = 7;
        EXPECT_EQ(rawstd_env_uint(env_name, 42, 0, UINT_MAX, &out), -EINVAL)
            << bad;
        EXPECT_EQ(out, 7u) << bad;
    }
    unsigned int out = 7;
    setenv(env_name, "0", 1);
    EXPECT_EQ(rawstd_env_uint(env_name, 42, 1, 100, &out), -EINVAL);
    setenv(env_name, "101", 1);
    EXPECT_EQ(rawstd_env_uint(env_name, 42, 1, 100, &out), -EINVAL);
    EXPECT_EQ(out, 7u);
}

TEST_F(EnvTest, bytes_defaults_and_units) {
    unsigned int out = 7;
    EXPECT_EQ(rawstd_env_bytes(env_name, 42, 0, UINT_MAX, &out), 0);
    EXPECT_EQ(out, 42u);
    setenv(env_name, "256M", 1);
    EXPECT_EQ(rawstd_env_bytes(env_name, 42, 0, UINT_MAX, &out), 0);
    EXPECT_EQ(out, 256u * 1024 * 1024);
    setenv(env_name, "123B", 1);
    EXPECT_EQ(rawstd_env_bytes(env_name, 42, 0, UINT_MAX, &out), 0);
    EXPECT_EQ(out, 123u);
}

TEST_F(EnvTest, bytes_rejects_bare_numbers_and_out_of_range_values) {
    for (const char* bad :
         {"", "123", "0", "4294967295", "-1K", "12Kjunk", "256MB", "4G",
          "4294967296B", "999999999999999999999999K"}) {
        setenv(env_name, bad, 1);
        unsigned int out = 7;
        EXPECT_EQ(rawstd_env_bytes(env_name, 42, 0, UINT_MAX, &out), -EINVAL)
            << bad;
        EXPECT_EQ(out, 7u) << bad;
    }
    unsigned int out = 7;
    setenv(env_name, "1K", 1);
    EXPECT_EQ(rawstd_env_bytes(env_name, 42, 0, 1023, &out), -EINVAL);
    EXPECT_EQ(out, 7u);
}

} // namespace
