#include <gtest/gtest.h>

#include <rawstorstd/gpp.hpp>

#include <rawstor/rawstor.h>

int main(int argc, char** argv) {
    if (rawstor_initialize(nullptr)) {
        RAWSTOR_THROW_ERRNO();
    }

    testing::InitGoogleTest(&argc, argv);

    int res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
