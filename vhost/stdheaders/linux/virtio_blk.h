#ifndef RAWSTOR_STDHEADERS_LINUX_VIRTIO_BLK_H
#define RAWSTOR_STDHEADERS_LINUX_VIRTIO_BLK_H

#include "stdheaders/linux/virtio_types.h"


#ifdef __cplusplus
extern "C" {
#endif


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


struct virtio_blk_config {
    /* The capacity (in 512-byte sectors). */
    __virtio64 capacity;
    /* The maximum segment size (if VIRTIO_BLK_F_SIZE_MAX) */
    __virtio32 size_max;
    /* The maximum number of segments (if VIRTIO_BLK_F_SEG_MAX) */
    __virtio32 seg_max;
    /* geometry of the device (if VIRTIO_BLK_F_GEOMETRY) */
    struct virtio_blk_geometry {
        __virtio16 cylinders;
        __u8 heads;
        __u8 sectors;
    } geometry;

    /* block size of device (if VIRTIO_BLK_F_BLK_SIZE) */
    __virtio32 blk_size;

    /* the next 4 entries are guarded by VIRTIO_BLK_F_TOPOLOGY  */
    /* exponent for physical block per logical block. */
    __u8 physical_block_exp;
    /* alignment offset in logical blocks. */
    __u8 alignment_offset;
    /* minimum I/O size without performance penalty in logical blocks. */
    __virtio16 min_io_size;
    /* optimal sustained I/O size in logical blocks. */
    __virtio32 opt_io_size;

    /* writeback mode (if VIRTIO_BLK_F_CONFIG_WCE) */
    __u8 wce;
    __u8 unused;

    /* number of vqs, only available when VIRTIO_BLK_F_MQ is set */
    __virtio16 num_queues;

    /* the next 3 entries are guarded by VIRTIO_BLK_F_DISCARD */
    /*
     * The maximum discard sectors (in 512-byte sectors) for
     * one segment.
     */
    __virtio32 max_discard_sectors;
    /*
     * The maximum number of discard segments in a
     * discard command.
     */
    __virtio32 max_discard_seg;
    /* Discard commands must be aligned to this number of sectors. */
    __virtio32 discard_sector_alignment;

    /* the next 3 entries are guarded by VIRTIO_BLK_F_WRITE_ZEROES */
    /*
     * The maximum number of write zeroes sectors (in 512-byte sectors) in
     * one segment.
     */
    __virtio32 max_write_zeroes_sectors;
    /*
     * The maximum number of segments in a write zeroes
     * command.
     */
    __virtio32 max_write_zeroes_seg;
    /*
     * Set if a VIRTIO_BLK_T_WRITE_ZEROES request may result in the
     * deallocation of one or more of the sectors.
     */
    __u8 write_zeroes_may_unmap;

    __u8 unused1[3];

    /* the next 3 entries are guarded by VIRTIO_BLK_F_SECURE_ERASE */
    /*
     * The maximum secure erase sectors (in 512-byte sectors) for
     * one segment.
     */
    __virtio32 max_secure_erase_sectors;
    /*
     * The maximum number of secure erase segments in a
     * secure erase command.
     */
    __virtio32 max_secure_erase_seg;
    /* Secure erase commands must be aligned to this number of sectors. */
    __virtio32 secure_erase_sector_alignment;

    /* Zoned block device characteristics (if VIRTIO_BLK_F_ZONED) */
    struct virtio_blk_zoned_characteristics {
        __virtio32 zone_sectors;
        __virtio32 max_open_zones;
        __virtio32 max_active_zones;
        __virtio32 max_append_sectors;
        __virtio32 write_granularity;
        __u8 model;
        __u8 unused2[3];
    } zoned;
} __attribute__((packed));


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_STDHEADERS_LINUX_VIRTIO_BLK_H
