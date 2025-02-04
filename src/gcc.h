#ifndef RAWSTOR_GCC_H
#define RAWSTOR_GCC_H


#if defined(__GNUC__) && (__GNUC__ >= 3)
#define RAWSTOR_UNUSED  __attribute__((unused))
#else
#define RAWSTOR_UNUSED
#endif


#endif // RAWSTOR_GCC_H
