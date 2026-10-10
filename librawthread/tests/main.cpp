#include <gtest/gtest.h>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

int main(int argc, char** argv) {
    int res = rawstd_logging_initialize();
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstd_logging_terminate();

    return res;
}
