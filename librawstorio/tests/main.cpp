#include <gtest/gtest.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

int main(int argc, char** argv) {
    if (rawstor_logging_initialize()) {
        RAWSTOR_THROW_ERRNO();
    }

    testing::InitGoogleTest(&argc, argv);

    int res = RUN_ALL_TESTS();

    rawstor_logging_terminate();

    return res;
}
