#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_TYPES_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_TYPES_H

#include "stdheaders/linux/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * __virtio{16,32,64} have the following meaning:
 * - __u{16,32,64} for virtio devices in legacy mode, accessed in native endian
 * - __le{16,32,64} for standard-compliant virtio devices
 */

typedef __u16 __bitwise __virtio16;
typedef __u32 __bitwise __virtio32;
typedef __u64 __bitwise __virtio64;


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_TYPES_H
