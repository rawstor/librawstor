#ifndef RAWSTOR_STDHEADERS_LINUX_VHOST_TYPES_H
#define RAWSTOR_STDHEADERS_LINUX_VHOST_TYPES_H

#include "stdheaders/linux/types.h"

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/* Log all write descriptors. Can be changed while device is active. */
#define VHOST_F_LOG_ALL 26


struct vhost_vring_state {
    unsigned int index;
    unsigned int num;
};


struct vhost_vring_addr {
    unsigned int index;
    /* Option flags. */
    unsigned int flags;
    /* Flag values: */
    /* Whether log address is valid. If set enables logging. */
#define VHOST_VRING_F_LOG 0

    /* Start of array of descriptors (virtually contiguous) */
    __u64 desc_user_addr;
    /* Used structure address. Must be 32 bit aligned */
    __u64 used_user_addr;
    /* Available structure address. Must be 16 bit aligned */
    __u64 avail_user_addr;
    /* Logging support. */
    /* Log writes to used structure, at offset calculated from specified
     * address. Address must be 32 bit aligned. */
    __u64 log_guest_addr;
};


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VHOST_TYPES_H
