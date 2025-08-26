#ifndef RAWSTORSTD_GCC_H
#define RAWSTORSTD_GCC_H


#ifdef __cplusplus
extern "C" {
#endif


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


#ifdef __cplusplus
}
#endif


#endif // RAWSTORSTD_GCC_H
