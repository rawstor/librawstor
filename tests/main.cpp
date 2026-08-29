#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

#include <cstdlib>

int main(int argc, char** argv) {
    // Several regression tests here (e.g. OstIOTest.write_disconnect_
    // concurrent) script an in-process fake OST server around the exact,
    // deterministic sequence and timing of reconnect attempts
    // Connection::_with_retry() makes with no backoff -- the real
    // RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE default (a real, if small, sleep
    // between attempts) shifts that timing enough to desync the fake
    // server's fixed script from the client's actual attempts, wedging a
    // test forever waiting on a response the script has no more of.
    // Disabled by default here for exactly that reason -- a real server
    // isn't scripted this way, so this isn't a production hazard, only a
    // test-harness one. `overwrite = 0` so an explicit environment
    // override (e.g. to test backoff itself) still wins.
    setenv("RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE", "0", 0);

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
