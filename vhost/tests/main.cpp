#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

#include <cstdlib>

int main(int argc, char** argv) {
    // See tests/main.cpp for why: some regression tests script a fake
    // OST server around the exact, backoff-free timing of
    // Connection::_with_retry()'s reconnect attempts. `overwrite = 0` so
    // an explicit environment override still wins.
    setenv("RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE", "0", 0);

    // rawstor_initialize() takes care of rawstd_logging_initialize() (and
    // undoes it via rawstor_terminate()) internally -- calling either
    // logging function directly here too, on top of it, would double up
    // (and, at rawstor_terminate() time, double-free) that setup. See
    // tests/main.cpp for the same pattern; vhost/tests/ only started
    // needing rawstor_initialize() itself once test_virtqueue_worker.cpp
    // started standing up real rawstor objects.
    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
