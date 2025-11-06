#ifndef RAWSTOR_VHOST_USER_PROTOCOL_H
#define RAWSTOR_VHOST_USER_PROTOCOL_H

#include <rawstorstd/gcc.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This code below was duplicated from linux/vhost.h header
 */

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY    24

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC 28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX     29

/* v1.0 compliant. */
#define VIRTIO_F_VERSION_1      32

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

/**
 * End of duplicated code from linux/vhost.h header
 */

/* Feature bits */
#define VIRTIO_BLK_F_SIZE_MAX     1   /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX      2   /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY     4   /* Legacy geometry available  */
#define VIRTIO_BLK_F_RO           5   /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE     6   /* Block size of disk is available*/
#define VIRTIO_BLK_F_TOPOLOGY     10  /* Topology information is available */
#define VIRTIO_BLK_F_MQ           12  /* support more than one vq */
#define VIRTIO_BLK_F_DISCARD      13  /* DISCARD is supported */
#define VIRTIO_BLK_F_WRITE_ZEROES 14  /* WRITE ZEROES is supported */
#define VIRTIO_BLK_F_SECURE_ERASE 16 /* Secure Erase is supported */
#define VIRTIO_BLK_F_ZONED        17  /* Zoned block device */

/* Legacy feature bits */
#define VIRTIO_BLK_F_BARRIER      0   /* Does host support barriers? */
#define VIRTIO_BLK_F_SCSI         7   /* Supports scsi command passthru */
#define VIRTIO_BLK_F_FLUSH        9   /* Flush command supported */
#define VIRTIO_BLK_F_CONFIG_WCE   11  /* Writeback mode available in config */
/* Old (deprecated) name for VIRTIO_BLK_F_FLUSH. */
#define VIRTIO_BLK_F_WCE VIRTIO_BLK_F_FLUSH

/* Based on qemu/hw/virtio/vhost-user.c */
#define VHOST_USER_F_PROTOCOL_FEATURES 30

#define VHOST_MEMORY_BASELINE_NREGIONS 8

/*
 * Maximum size of virtio device config space
 */
#define VHOST_USER_MAX_CONFIG_SIZE 256

#define UUID_LEN 16


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
    VHOST_USER_POSTCOPY_ADVISE  = 28,
    VHOST_USER_POSTCOPY_LISTEN  = 29,
    VHOST_USER_POSTCOPY_END     = 30,
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


typedef struct {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     (0x3)
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
#define VHOST_USER_NEED_REPLY_MASK  (0x1 << 3)
    uint32_t flags;
    uint32_t size; /* the following payload size */
} RAWSTOR_PACKED VhostUserHeader;


typedef union {
#define VHOST_USER_VRING_IDX_MASK   (0xff)
#define VHOST_USER_VRING_NOFD_MASK  (0x1 << 8)
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
} RAWSTOR_PACKED VhostUserPayload;


typedef struct {
    int fds[VHOST_MEMORY_BASELINE_NREGIONS];
    int nfds;
} RAWSTOR_PACKED VhostUserFds;


typedef struct {
	/**
     *  The capacity (in 512-byte sectors).
     */
	uint64_t capacity;

	/**
     * The maximum segment size (if VIRTIO_BLK_F_SIZE_MAX)
     */
	uint32_t size_max;

	/**
     * The maximum number of segments (if VIRTIO_BLK_F_SEG_MAX)
     */
	uint32_t seg_max;

	/**
     * Geometry of the device (if VIRTIO_BLK_F_GEOMETRY)
     */
	struct virtio_blk_geometry {
		uint16_t cylinders;
		uint8_t heads;
		uint8_t sectors;
	} geometry;

	/**
     * Block size of device (if VIRTIO_BLK_F_BLK_SIZE)
     */
	uint32_t blk_size;

	/**
     * The next 4 entries are guarded by VIRTIO_BLK_F_TOPOLOGY
     */

	/**
     * Exponent for physical block per logical block.
     */
	uint8_t physical_block_exp;

	/**
     * Alignment offset in logical blocks.
     */
	uint8_t alignment_offset;

	/**
     * Minimum I/O size without performance penalty in logical blocks.
     */
	uint16_t min_io_size;

	/**
     * Optimal sustained I/O size in logical blocks.
     */
	uint32_t opt_io_size;

	/**
     * Writeback mode (if VIRTIO_BLK_F_CONFIG_WCE)
     */
	uint8_t wce;

	uint8_t unused;

	/**
     * Number of vqs, only available when VIRTIO_BLK_F_MQ is set
     */
	uint16_t num_queues;

	/**
     * The next 3 entries are guarded by VIRTIO_BLK_F_DISCARD
     */

	/**
	 * The maximum discard sectors (in 512-byte sectors) for
	 * one segment.
	 */
	uint32_t max_discard_sectors;

	/**
	 * The maximum number of discard segments in a
	 * discard command.
	 */
	uint32_t max_discard_seg;

	/**
     * Discard commands must be aligned to this number of sectors.
     */
	uint32_t discard_sector_alignment;

	/**
     * The next 3 entries are guarded by VIRTIO_BLK_F_WRITE_ZEROES
     */

	/**
	 * The maximum number of write zeroes sectors (in 512-byte sectors) in
	 * one segment.
	 */
	uint32_t max_write_zeroes_sectors;

	/**
	 * The maximum number of segments in a write zeroes
	 * command.
	 */
	uint32_t max_write_zeroes_seg;

	/**
	 * Set if a VIRTIO_BLK_T_WRITE_ZEROES request may result in the
	 * deallocation of one or more of the sectors.
	 */
	uint8_t write_zeroes_may_unmap;

	uint8_t unused1[3];

	/**
     * The next 3 entries are guarded by VIRTIO_BLK_F_SECURE_ERASE
     */

	/**
	 * The maximum secure erase sectors (in 512-byte sectors) for
	 * one segment.
	 */
	uint32_t max_secure_erase_sectors;

	/**
	 * The maximum number of secure erase segments in a
	 * secure erase command.
	 */
	uint32_t max_secure_erase_seg;

	/**
     * Secure erase commands must be aligned to this number of sectors.
     */
	uint32_t secure_erase_sector_alignment;

	/**
     * Zoned block device characteristics (if VIRTIO_BLK_F_ZONED)
     */
	struct virtio_blk_zoned_characteristics {
		uint32_t zone_sectors;
		uint32_t max_open_zones;
		uint32_t max_active_zones;
		uint32_t max_append_sectors;
		uint32_t write_granularity;
		uint8_t model;
		uint8_t unused2[3];
	} zoned;
} RAWSTOR_PACKED VirtioBlkConfig;



#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_VHOST_SERVER_H
