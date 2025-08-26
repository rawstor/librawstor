#ifndef RAWSTOR_TEST_UNITTEST_H
#define RAWSTOR_TEST_UNITTEST_H


#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


#define assertTrue(expr) do { \
    if (!(expr)) { \
        fprintf( \
            stderr, "%s:%d Assertion failed: %s\n", \
            __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_TEST_UNITTEST_H
