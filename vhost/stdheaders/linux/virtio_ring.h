#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H


#ifdef __cplusplus
extern "C" {
#endif


/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC 28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX     29


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H
