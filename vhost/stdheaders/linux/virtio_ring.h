#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H

#include "stdheaders/linux/virtio_types.h"

#include <string.h>


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

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT       1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE      2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT   4

/* The Guest uses this in avail->flags to advise that no interrupts
 * are needed. */
#define VRING_AVAIL_F_NO_INTERRUPT  1

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer. */
#define VRING_USED_F_NO_NOTIFY  1


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

/*
 * When VIRTIO_RING_F_EVENT_IDX has been negotiated, the avail and used rings
 * grow one extra element used to carry an event index instead of a flag:
 * the "used event" is stored past the end of the avail ring, and the
 * "avail event" is stored past the end of the used ring.
 */
#define vring_used_event(num, avail) \
    ((avail)->ring[(num)])

/*
 * The avail_event slot overlaps the (unused) trailing used-ring element and
 * is not naturally aligned as a __virtio16, so it is accessed via memcpy()
 * rather than a reinterpret-casted pointer to avoid violating strict
 * aliasing.
 */
static inline __virtio16 vring_avail_event_get(
    unsigned int num, const struct vring_used *used
) {
    __virtio16 value;
    memcpy(&value, &used->ring[num], sizeof(value));
    return value;
}

static inline void vring_avail_event_set(
    unsigned int num, struct vring_used *used, __virtio16 value
) {
    memcpy(&used->ring[num], &value, sizeof(value));
}


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_RING_H
