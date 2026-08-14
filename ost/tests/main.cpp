#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

int main(int argc, char** argv) {
    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
