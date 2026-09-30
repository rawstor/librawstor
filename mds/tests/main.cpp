#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>

#include <rawstor/rawstor.h>

int main(int argc, char** argv) {
    // ObjectStore/place()'s own error paths log via rawstd_error() before
    // throwing (the same log-then-throw convention every other component
    // uses) -- rawstd_logging_mutex stays NULL, and a lock on it
    // segfaults, until rawstor_initialize() creates it.
    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_terminate();

    return res;
}
