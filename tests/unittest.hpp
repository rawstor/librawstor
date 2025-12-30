#ifndef RAWSTOR_TEST_UNITTEST_HPP
#define RAWSTOR_TEST_UNITTEST_HPP

#include "unittest.h"

#define assertThrow(expr, exc)                                                 \
    do {                                                                       \
        int caught = 0;                                                        \
        try {                                                                  \
            expr;                                                              \
        } catch (const exc&) {                                                 \
            caught = 1;                                                        \
        }                                                                      \
        assertTrue(caught == 1);                                               \
    } while (0)

#endif // RAWSTOR_TEST_UNITTEST_HPP
