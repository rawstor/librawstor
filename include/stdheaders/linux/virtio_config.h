#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_CONFIG_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_CONFIG_H

#include <stdheaders/linux/virtio_types.h>


#ifdef __cplusplus
extern "C" {
#endif


/* Status byte for guest to report progress (e.g. VDUSE_SET_STATUS / the
 * device's own config status field). */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE 1
#define VIRTIO_CONFIG_S_DRIVER      2
#define VIRTIO_CONFIG_S_DRIVER_OK   4
#define VIRTIO_CONFIG_S_FEATURES_OK 8
#define VIRTIO_CONFIG_S_NEEDS_RESET 0x40
#define VIRTIO_CONFIG_S_FAILED      0x80

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY    24

/* v1.0 compliant. */
#define VIRTIO_F_VERSION_1      32

/* Access to device-specific memory is only possible via translated
 * addresses (an IOMMU or, for VDUSE, the kernel's own IOVA/IOTLB
 * indirection) -- the VDUSE kernel driver requires this bit to be
 * negotiated. */
#define VIRTIO_F_ACCESS_PLATFORM    33


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_CONFIG_H
