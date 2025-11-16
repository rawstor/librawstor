#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H

#include "stdheaders/linux/virtio_types.h"


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

#define VRING_USED_ALIGN_SIZE 4


/**
 * struct vring_desc - Virtio ring descriptors,
 * 16 bytes long. These can chain together via @next.
 *
 * @addr: buffer address (guest-physical)
 * @len: buffer length
 * @flags: descriptor flags
 * @next: index of the next descriptor in the chain,
 *        if the VRING_DESC_F_NEXT flag is set. We chain unused
 *        descriptors via this, too.
 */
struct vring_desc {
    __virtio64 addr;
    __virtio32 len;
    __virtio16 flags;
    __virtio16 next;
};

struct vring_avail {
    __virtio16 flags;
    __virtio16 idx;
    __virtio16 ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem {
    /* Index of start of used descriptor chain. */
    __virtio32 id;
    /* Total length of the descriptor chain which was used (written to) */
    __virtio32 len;
};

typedef struct vring_used_elem __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
    vring_used_elem_t;

struct vring_used {
    __virtio16 flags;
    __virtio16 idx;
    vring_used_elem_t ring[];
};


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H
