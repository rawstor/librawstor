#ifndef RAWSTOR_VU_GCC_H
#define RAWSTOR_VU_GCC_H


#if defined(__GNUC__) && (__GNUC__ >= 3)
#define RAWSTOR_VU_UNUSED  __attribute__((unused))
#else
#define RAWSTOR_VU_UNUSED
#endif


#define RAWSTOR_VU_PACKED __attribute__((packed))


#endif // RAWSTOR_VU_GCC_H
