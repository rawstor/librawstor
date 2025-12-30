#ifndef RAWSTOR_VHOST_USER_PROTOCOL_H
#define RAWSTOR_VHOST_USER_PROTOCOL_H

#if defined(__linux__)
#include <linux/vhost.h>
#else
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY 24

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC 28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX 29

/* v1.0 compliant. */
#define VIRTIO_F_VERSION_1 32

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
    uint64_t desc_user_addr;
    /* Used structure address. Must be 32 bit aligned */
    uint64_t used_user_addr;
    /* Available structure address. Must be 16 bit aligned */
    uint64_t avail_user_addr;
    /* Logging support. */
    /* Log writes to used structure, at offset calculated from specified
     * address. Address must be 32 bit aligned. */
    uint64_t log_guest_addr;
};
#endif

#include <stdint.h>

#define RAWSTOR_VU_PACKED __attribute__((packed))

/* Based on qemu/hw/virtio/vhost-user.c */
#define VHOST_USER_F_PROTOCOL_FEATURES 30

#define VHOST_MEMORY_BASELINE_NREGIONS 8

/*
 * Maximum size of virtio device config space
 */
#define VHOST_USER_MAX_CONFIG_SIZE 256

#define UUID_LEN 16

#define VHOST_USER_HDR_SIZE offsetof(VhostUserMsg, payload)

typedef struct VhostUserMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t mmap_offset;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    uint32_t nregions;
    uint32_t padding;
    VhostUserMemoryRegion regions[VHOST_MEMORY_BASELINE_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserMemRegMsg {
    uint64_t padding;
    VhostUserMemoryRegion region;
} VhostUserMemRegMsg;

typedef struct VhostUserLog {
    uint64_t mmap_size;
    uint64_t mmap_offset;
} VhostUserLog;

typedef struct VhostUserConfig {
    uint32_t offset;
    uint32_t size;
    uint32_t flags;
    uint8_t region[VHOST_USER_MAX_CONFIG_SIZE];
} VhostUserConfig;

typedef struct VhostUserVringArea {
    uint64_t u64;
    uint64_t size;
    uint64_t offset;
} VhostUserVringArea;

typedef struct VhostUserInflight {
    uint64_t mmap_size;
    uint64_t mmap_offset;
    uint16_t num_queues;
    uint16_t queue_size;
} VhostUserInflight;

typedef struct VhostUserShared {
    unsigned char uuid[UUID_LEN];
} VhostUserShared;

enum VhostUserProtocolFeature {
    VHOST_USER_PROTOCOL_F_MQ = 0,
    VHOST_USER_PROTOCOL_F_LOG_SHMFD = 1,
    VHOST_USER_PROTOCOL_F_RARP = 2,
    VHOST_USER_PROTOCOL_F_REPLY_ACK = 3,
    VHOST_USER_PROTOCOL_F_NET_MTU = 4,
    VHOST_USER_PROTOCOL_F_BACKEND_REQ = 5,
    VHOST_USER_PROTOCOL_F_CROSS_ENDIAN = 6,
    VHOST_USER_PROTOCOL_F_CRYPTO_SESSION = 7,
    VHOST_USER_PROTOCOL_F_PAGEFAULT = 8,
    VHOST_USER_PROTOCOL_F_CONFIG = 9,
    VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD = 10,
    VHOST_USER_PROTOCOL_F_HOST_NOTIFIER = 11,
    VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD = 12,
    VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS = 14,
    VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS = 15,
    /* Feature 16 is reserved for VHOST_USER_PROTOCOL_F_STATUS. */
    /* Feature 17 reserved for VHOST_USER_PROTOCOL_F_XEN_MMAP. */
    VHOST_USER_PROTOCOL_F_SHARED_OBJECT = 18,
    VHOST_USER_PROTOCOL_F_MAX
};

typedef enum VhostUserRequest {
    VHOST_USER_NONE = 0,
    VHOST_USER_GET_FEATURES = 1,
    VHOST_USER_SET_FEATURES = 2,
    VHOST_USER_SET_OWNER = 3,
    VHOST_USER_RESET_OWNER = 4,
    VHOST_USER_SET_MEM_TABLE = 5,
    VHOST_USER_SET_LOG_BASE = 6,
    VHOST_USER_SET_LOG_FD = 7,
    VHOST_USER_SET_VRING_NUM = 8,
    VHOST_USER_SET_VRING_ADDR = 9,
    VHOST_USER_SET_VRING_BASE = 10,
    VHOST_USER_GET_VRING_BASE = 11,
    VHOST_USER_SET_VRING_KICK = 12,
    VHOST_USER_SET_VRING_CALL = 13,
    VHOST_USER_SET_VRING_ERR = 14,
    VHOST_USER_GET_PROTOCOL_FEATURES = 15,
    VHOST_USER_SET_PROTOCOL_FEATURES = 16,
    VHOST_USER_GET_QUEUE_NUM = 17,
    VHOST_USER_SET_VRING_ENABLE = 18,
    VHOST_USER_SEND_RARP = 19,
    VHOST_USER_NET_SET_MTU = 20,
    VHOST_USER_SET_BACKEND_REQ_FD = 21,
    VHOST_USER_IOTLB_MSG = 22,
    VHOST_USER_SET_VRING_ENDIAN = 23,
    VHOST_USER_GET_CONFIG = 24,
    VHOST_USER_SET_CONFIG = 25,
    VHOST_USER_CREATE_CRYPTO_SESSION = 26,
    VHOST_USER_CLOSE_CRYPTO_SESSION = 27,
    VHOST_USER_POSTCOPY_ADVISE = 28,
    VHOST_USER_POSTCOPY_LISTEN = 29,
    VHOST_USER_POSTCOPY_END = 30,
    VHOST_USER_GET_INFLIGHT_FD = 31,
    VHOST_USER_SET_INFLIGHT_FD = 32,
    VHOST_USER_GPU_SET_SOCKET = 33,
    VHOST_USER_RESET_DEVICE = 34,
    /* Message number 35 reserved for VHOST_USER_VRING_KICK. */
    VHOST_USER_GET_MAX_MEM_SLOTS = 36,
    VHOST_USER_ADD_MEM_REG = 37,
    VHOST_USER_REM_MEM_REG = 38,
    VHOST_USER_SET_STATUS = 39,
    VHOST_USER_GET_STATUS = 40,
    VHOST_USER_GET_SHARED_OBJECT = 41,
    VHOST_USER_SET_DEVICE_STATE_FD = 42,
    VHOST_USER_CHECK_DEVICE_STATE = 43,
    VHOST_USER_MAX
} VhostUserRequest;

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK (0x3)
#define VHOST_USER_REPLY_MASK (0x1 << 2)
#define VHOST_USER_NEED_REPLY_MASK (0x1 << 3)
    uint32_t flags;
    uint32_t size; /* the following payload size */
    union {
#define VHOST_USER_VRING_IDX_MASK (0xff)
#define VHOST_USER_VRING_NOFD_MASK (0x1 << 8)
        uint64_t u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        VhostUserMemory memory;
        VhostUserMemRegMsg memreg;
        VhostUserLog log;
        VhostUserConfig config;
        VhostUserVringArea area;
        VhostUserInflight inflight;
        VhostUserShared object;
    } payload;

    int fds[VHOST_MEMORY_BASELINE_NREGIONS];
    int fd_num;
    uint8_t* data;
} RAWSTOR_VU_PACKED VhostUserMsg;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_VHOST_SERVER_H
