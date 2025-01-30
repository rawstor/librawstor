#ifndef RAWSTOR_TEST_UTILS_H
#define RAWSTOR_TEST_UTILS_H


#include <stdio.h>


#define assertTrue(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d Assertion failed: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)


#endif // RAWSTOR_TEST_UTILS_H
