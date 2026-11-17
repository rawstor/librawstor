#include <rawstd/target.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>
#include <string>

namespace {

const char* const U = "019cbfad-a389-7d42-a0f6-c29993ac8c00";
const char* const V = "018f4e2a-3000-7000-8000-000000000001";

class TargetTest : public testing::Test {
protected:
    void SetUp() override { unsetenv("RAWSTOR_LOCATION"); }
    void TearDown() override { unsetenv("RAWSTOR_LOCATION"); }

    static std::string resolve(
        const std::string& first, const char* second, int expected_consumed
    ) {
        int consumed = 0;
        char* r = rawstd_target_resolve(first.c_str(), second, &consumed);
        EXPECT_NE(r, nullptr);
        EXPECT_EQ(consumed, expected_consumed);
        std::string result = r != nullptr ? r : "";
        free(r);
        return result;
    }
};

TEST_F(TargetTest, FullTargetIsReturnedAsIs) {
    std::string t = std::string("ost://h:1/") + U;
    EXPECT_EQ(resolve(t, nullptr, 1), t);
    // A target followed by another argument (e.g. an account) stays alone.
    EXPECT_EQ(resolve(t, V, 1), t);
    t += std::string("/") + V;
    EXPECT_EQ(resolve(t, V, 1), t);
}

TEST_F(TargetTest, LocationAndUuid) {
    EXPECT_EQ(
        resolve("ost://h:1", U, 2), std::string("ost://h:1/") + U
    );
    EXPECT_EQ(
        resolve("ost://h:1/", U, 2), std::string("ost://h:1/") + U
    );
    EXPECT_EQ(
        resolve("file:///var/rawstor", U, 2),
        std::string("file:///var/rawstor/") + U
    );
    EXPECT_EQ(
        resolve("ost://a:1,ost://b:2", U, 2),
        std::string("ost://a:1/") + U + ",ost://b:2/" + U
    );
    EXPECT_EQ(
        resolve("mds://h:1", (std::string(U) + "/" + V).c_str(), 2),
        std::string("mds://h:1/") + U + "/" + V
    );
    EXPECT_EQ(
        resolve("mds://h:1", (std::string(U) + "/0").c_str(), 2),
        std::string("mds://h:1/") + U + "/0"
    );
}

TEST_F(TargetTest, BareUuidUsesEnvLocation) {
    setenv("RAWSTOR_LOCATION", "ost://a:1,ost://b:2", 1);
    EXPECT_EQ(
        resolve(U, nullptr, 1),
        std::string("ost://a:1/") + U + ",ost://b:2/" + U
    );
    // The second argument (an account) is not part of the target.
    EXPECT_EQ(
        resolve(U, V, 1), std::string("ost://a:1/") + U + ",ost://b:2/" + U
    );
}

TEST_F(TargetTest, BareUuidWithoutEnvFails) {
    int consumed = 0;
    errno = 0;
    EXPECT_EQ(rawstd_target_resolve(U, nullptr, &consumed), nullptr);
    EXPECT_EQ(errno, ENOENT);

    setenv("RAWSTOR_LOCATION", "", 1);
    errno = 0;
    EXPECT_EQ(rawstd_target_resolve(U, nullptr, &consumed), nullptr);
    EXPECT_EQ(errno, ENOENT);
}

TEST_F(TargetTest, NotAnIdIsPassedThrough) {
    EXPECT_EQ(resolve("ost://h:1", "nonsense", 1), "ost://h:1");
    EXPECT_EQ(resolve("ost://h:1", nullptr, 1), "ost://h:1");
}

} // namespace
