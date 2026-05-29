#ifndef RAWSTD_ENDIAN_H
#define RAWSTD_ENDIAN_H

#include <rawstd/gcc.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(RAWSTD_ON_MACOS)

#include <libkern/OSByteOrder.h>

#define RAWSTD_LE16TOH(x) OSSwapLittleToHostInt16(x)
#define RAWSTD_LE32TOH(x) OSSwapLittleToHostInt32(x)
#define RAWSTD_LE64TOH(x) OSSwapLittleToHostInt64(x)

#else

#include <endian.h>

#define RAWSTD_LE16TOH(x) le16toh(x)
#define RAWSTD_LE32TOH(x) le32toh(x)
#define RAWSTD_LE64TOH(x) le64toh(x)

#endif

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_ENDIAN_H
