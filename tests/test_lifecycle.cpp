#include "fixture.hpp"

#include <rawstor/object.h>

#include <rawstorstd/gpp.hpp>

#include <gtest/gtest.h>

#include <cstring>

namespace {

using namespace rawstor::tests;

TEST_F(ObjectTest, create_spec_remove) {
    RawstorObjectSpec spec{.size = 1ull << 20};
    char object_uris[1024] = {};
    int res =
        rawstor_object_create(uris(), &spec, object_uris, sizeof(object_uris));
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, (int)strlen(object_uris));

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(object_uris, &read_spec);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    res = rawstor_object_remove(object_uris);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, 0);
}

} // unnamed namespace
