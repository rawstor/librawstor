#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

#include <cstdlib>

int main(int argc, char** argv) {
    /* Keep the mirror rejoin tests fast; do not override a user setting. */
    setenv("RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL", "200", 0);

    /*
     * test_mirror.cpp's read_failover_and_repair scripts exactly 3 mock
     * server sessions to match this default; pin it so the test does not
     * silently desync from a future default change or a user override.
     */
    setenv("RAWSTOR_OPTS_IO_ATTEMPTS", "3", 0);

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
