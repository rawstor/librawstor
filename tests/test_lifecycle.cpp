#include "backend.hpp"
#include "server.hpp"

#include <rawstd/gpp.hpp>

#include <rawstor/object.h>

#include <gtest/gtest.h>

#include <cstring>

namespace {

class LifecycleTest
    : public testing::TestWithParam<std::shared_ptr<rawstor::tests::Backend>> {
protected:
    std::shared_ptr<rawstor::tests::Backend> _backend;

    void SetUp() override { _backend = GetParam(); }
};

TEST_P(LifecycleTest, create_spec_remove) {
    _backend->accept();
    RawstorObjectSpec spec{.size = 1ull << 20};
    char target[1024] = {};
    int res = rawstor_object_create(
        _backend->uris().c_str(), &spec, target, sizeof(target)
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, (int)strlen(target));
    _backend->close();

    _backend->accept();
    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target, &read_spec);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    EXPECT_EQ(res, 0);
    if (_backend->protocol() == "ost") {
        // rawstor_object_spec emulated
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 30));
    } else {
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }
    _backend->close();

    // rawstor_object_remove not implemented for OST
    if (_backend->protocol() != "ost") {
        _backend->accept();
        res = rawstor_object_remove(target);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        EXPECT_EQ(res, 0);
        _backend->close();
    }
}

INSTANTIATE_TEST_SUITE_P(
    AllBackends, LifecycleTest, ::testing::ValuesIn(rawstor::tests::backends),
    [](const ::testing::TestParamInfo<std::shared_ptr<rawstor::tests::Backend>>&
           info) { return info.param->protocol(); }
);

} // unnamed namespace
