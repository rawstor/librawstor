#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

#include <cstdlib>

int main(int argc, char** argv) {
    // ObjectStore/place()'s own error paths log via rawstd_error() before
    // throwing (the same log-then-throw convention every other component
    // uses) -- rawstd_logging_mutex stays NULL, and a lock on it
    // segfaults, until rawstor_initialize() creates it.
    setenv("RAWSTOR_OPTS_IO_ATTEMPTS", "3", 0);
    setenv("RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE", "0", 0);
    // These suites talk to a fake or an in-process server without a
    // certificate: without TLS settings a process refuses to start unless it
    // is told to go without TLS. `overwrite = 0` so an explicit environment
    // still wins; the TLS tests set up their own.
    setenv("RAWSTOR_INSECURE", "1", 0);

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
