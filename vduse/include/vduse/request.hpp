#ifndef RAWSTOR_VDUSE_REQUEST_HPP
#define RAWSTOR_VDUSE_REQUEST_HPP

#include <sys/uio.h>

#include <cstdint>

namespace rawstor {
namespace vduse {

/**
 * Splits a virtio-blk request's device-readable ("out") and
 * device-writable ("in") iovec arrays -- as popped off a virtqueue -- into
 * the leading virtio_blk_outhdr, the read/write payload, and the trailing
 * one-byte status footer.
 *
 * This is pure iovec arithmetic: it doesn't know about vduse, virtqueues,
 * or any other transport, so it can be exercised directly in tests/ without
 * a live VDUSE device.
 */
class BlkRequest final {
private:
    iovec* _in_iov;
    unsigned int _in_niov;
    iovec* _out_iov;
    unsigned int _out_niov;
    unsigned char* _status;
    uint32_t _type;
    uint64_t _offset;

public:
    /**
     * @param out_iov/out_niov  Device-readable descriptors (request header,
     *                          then write payload for VIRTIO_BLK_T_OUT).
     * @param in_iov/in_niov    Device-writable descriptors (read payload for
     *                          VIRTIO_BLK_T_IN, then the status footer).
     *
     * Throws std::system_error(EINVAL) if either array is too short to hold
     * the header or footer it is expected to carry.
     */
    BlkRequest(
        iovec* out_iov, unsigned int out_niov, iovec* in_iov,
        unsigned int in_niov
    );

    /** Device-writable iovecs, past the header and short of the footer. */
    inline iovec* in_iov() const noexcept { return _in_iov; }

    inline unsigned int in_niov() const noexcept { return _in_niov; }

    /** Device-readable iovecs, past the header. */
    inline iovec* out_iov() const noexcept { return _out_iov; }

    inline unsigned int out_niov() const noexcept { return _out_niov; }

    /** VIRTIO_BLK_T_* request type, with the barrier bit masked off. */
    inline uint32_t type() const noexcept { return _type; }

    /** Byte offset into the object, decoded from the header's sector. */
    inline uint64_t offset() const noexcept { return _offset; }

    /** Write the virtio-blk status byte into the trailing footer. */
    inline void set_status(unsigned char status) noexcept { *_status = status; }
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_REQUEST_HPP
