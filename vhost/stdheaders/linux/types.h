#ifndef RAWSTOR_STDHEADERS_LINUX_TYPES_H
#define RAWSTOR_STDHEADERS_LINUX_TYPES_H

#include <rawstorstd/gcc.h>


#ifdef __cplusplus
extern "C" {
#endif


#if defined(RAWSTOR_ON_LINUX)

#include <linux/types.h>

#else // RAWSTOR_ON_LINUX

#include "stdint.h"

typedef int8_t __s8;
typedef uint8_t __u8;
typedef int16_t __s16;
typedef uint16_t __u16;
typedef int32_t __s32;
typedef uint32_t __u32;
typedef int64_t __s64;
typedef uint64_t __u64;

#ifdef __CHECKER__
#define __bitwise   __attribute__((bitwise))
#else
#define __bitwise
#endif

#endif // RAWSTOR_ON_LINUX


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_TYPES_H
