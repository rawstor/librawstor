#ifndef RAWSTOR_STD_GCC_H
#define RAWSTOR_STD_GCC_H


#if defined(__GNUC__) && (__GNUC__ >= 3)
#define RAWSTOR_UNUSED  __attribute__((unused))
#else
#define RAWSTOR_UNUSED
#endif


#define RAWSTOR_PACKED __attribute__((packed))


#ifdef __APPLE__
#define RAWSTOR_ON_MACOS
#endif

#ifdef __linux__
#define RAWSTOR_ON_LINUX
#endif


#endif // RAWSTOR_STD_GCC_H
