#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_CONFIG_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_CONFIG_H


#ifdef __cplusplus
extern "C" {
#endif


/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY    24

/* v1.0 compliant. */
#define VIRTIO_F_VERSION_1      32


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_CONFIG_H
