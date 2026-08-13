#include <gtest/gtest.h>

// Deliberately does not wrap RUN_ALL_TESTS() in its own
// rawstor_initialize()/rawstor_terminate() (or even just
// rawstd_logging_initialize()/_terminate()): ostbackend::Server's own
// constructor/destructor already call those, and each test here
// constructs its own, non-overlapping Server -- an outer pair here would
// double up on the mutex rawstd_logging_{initialize,terminate}() creates
// and destroys (created again, then destroyed twice: once by a Server
// mid-run, again by this main() at the end).
int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
