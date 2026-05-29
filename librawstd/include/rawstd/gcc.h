#ifndef RAWSTD_GCC_H
#define RAWSTD_GCC_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define RAWSTD_UNUSED __attribute__((unused))
#else
#define RAWSTD_UNUSED
#endif

#ifdef __APPLE__
#define RAWSTD_ON_MACOS
#endif

#ifdef __linux__
#define RAWSTD_ON_LINUX
#endif

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_GCC_H
