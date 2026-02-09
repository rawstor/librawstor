#include <gtest/gtest.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

int main(int argc, char** argv) {
    int res = rawstor_logging_initialize();
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    testing::InitGoogleTest(&argc, argv);

    res = RUN_ALL_TESTS();

    rawstor_logging_terminate();

    return res;
}
