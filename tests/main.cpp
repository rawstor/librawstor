#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

#include <cstdlib>

int main(int argc, char** argv) {
    /* Keep the mirror rejoin tests fast; do not override a user setting. */
    setenv("RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL", "200", 0);

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
