#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>

#include <rawstor/object.h>

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>

namespace {

TEST(FileLifecycleTest, create_spec_remove) {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() / "test_objects";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string location = oss.str();

    RawstorObjectSpec spec{.size = 1ull << 20};
    std::string target(1024, '\0');
    int res = rawstor_object_create(
        location.c_str(), &spec, target.data(), target.size()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_GT(res, 0);
    EXPECT_LE(res, (int)target.size());
    target.resize(res);

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target.c_str(), &read_spec);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    res = rawstor_object_remove(target.c_str());
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, 0);
}

TEST(OstLifecycleTest, create_spec_remove) {
    rawstor::tests::Server server(8753);
    std::string location = "ost://127.0.0.1:8753";

    std::string target(1024, '\0');
    {
        rawstor::tests::Session s(server);

        RawstorObjectSpec spec{.size = 1ull << 20};

        int res = rawstor_object_create(
            location.c_str(), &spec, target.data(), target.size()
        );
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        EXPECT_GT(res, 0);
        EXPECT_LE(res, (int)target.size());
        target.resize(res);
    }

    {
        rawstor::tests::Session s(server);

        RawstorObjectSpec read_spec;
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        EXPECT_EQ(res, 0);
        // rawstor_object_spec emulated
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 30));
    }

    {
        // rawstor_object_remove not implemented for OST
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, -EINVAL);
    }
}

} // unnamed namespace
