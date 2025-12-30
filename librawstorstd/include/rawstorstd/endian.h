#ifndef RAWSTORSTD_ENDIAN_H
#define RAWSTORSTD_ENDIAN_H

#include <rawstorstd/gcc.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(RAWSTOR_ON_MACOS)

#include <libkern/OSByteOrder.h>

#define RAWSTOR_LE16TOH(x) OSSwapLittleToHostInt16(x)
#define RAWSTOR_LE32TOH(x) OSSwapLittleToHostInt32(x)
#define RAWSTOR_LE64TOH(x) OSSwapLittleToHostInt64(x)

#else

#include <endian.h>

#define RAWSTOR_LE16TOH(x) le16toh(x)
#define RAWSTOR_LE32TOH(x) le32toh(x)
#define RAWSTOR_LE64TOH(x) le64toh(x)

#endif

#ifdef __cplusplus
}
#endif

#endif // RAWSTORSTD_ENDIAN_H
