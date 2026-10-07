#ifndef RAWSTOR_VDUSE_INFLIGHT_HPP
#define RAWSTOR_VDUSE_INFLIGHT_HPP

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vduse {

/**
 * Per-virtqueue log of which descriptor heads have been popped but not
 * yet completed, laid out exactly as vhost-user's in-flight memory
 * (libvhost-user's VuVirtqInflight, split ring only). VDUSE has no
 * equivalent of its own, so Device keeps these in a file under /dev/shm
 * that outlives the process: a restarted rawstor-vduse reattaching to
 * the same device resubmits whatever its previous instance left in
 * flight -- see VirtQueue::set_inflight().
 */
struct InflightDesc {
    /* 1 while this head is popped but not yet completed. */
    uint8_t inflight;
    uint8_t padding[5];
    /* Unused (no batched completions). */
    uint16_t next;
    /* Pop order, so heads can be resubmitted in the order they arrived. */
    uint64_t counter;
};
static_assert(sizeof(InflightDesc) == 16);

struct InflightRegion {
    uint64_t features;
    /* 0 until a back-end has initialized it (a fresh region, or one the
     * front-end has reset along with the device). */
    uint16_t version;
    /* Number of entries in `desc`, the virtqueue's maximum size. */
    uint16_t desc_num;
    /* Head of the completion being published right now: cleared by the
     * next back-end if it died between publishing used->idx and clearing
     * that head's `inflight`. */
    uint16_t last_batch_head;
    /* used->idx as of the last completion fully recorded here. */
    uint16_t used_idx;
    InflightDesc desc[];
};
static_assert(sizeof(InflightRegion) == 16);

inline constexpr uint16_t inflight_version = 1;

/** Bytes one virtqueue's InflightRegion takes for `queue_size` heads,
 * each region 64-byte aligned within the shared memory. */
inline constexpr size_t inflight_region_size(uint16_t queue_size) {
    size_t size = sizeof(InflightRegion) + sizeof(InflightDesc) * queue_size;
    return (size + 63) & ~static_cast<size_t>(63);
}

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_INFLIGHT_HPP
