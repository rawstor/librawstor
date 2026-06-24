#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>

#include <rawstor/object.h>

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>

namespace {

TEST(FileLifecycleTest, create_spec_remove) {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 "test_objects" /
                                 "00000000-0000-7000-8000-000000000000";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string target = oss.str();

    RawstorObjectSpec spec{.size = 1ull << 20};
    int res = rawstor_object_create(target.c_str(), &spec);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(OstLifecycleTest, create_spec_remove) {
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);

        RawstorObjectSpec spec{.size = 1ull << 20};

        int res = rawstor_object_create(target.c_str(), &spec);
        EXPECT_EQ(res, 0);
    }

    {
        rawstor::tests::Session s(server);

        RawstorObjectSpec read_spec;
        int res = rawstor_object_spec(target.c_str(), &read_spec);
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
