#include <vduse/request.hpp>

#include <stdheaders/linux/virtio_blk.h>

#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <cerrno>

#define VIRTIO_BLK_SECTOR_BITS 9

namespace rawstor {
namespace vduse {

BlkRequest::BlkRequest(
    iovec* out_iov, unsigned int out_niov, iovec* in_iov, unsigned int in_niov
) :
    _in_iov(in_iov),
    _in_niov(in_niov),
    _out_iov(out_iov),
    _out_niov(out_niov) {
    virtio_blk_outhdr hdr;

    if (_out_niov == 0 ||
        rawstd_iovec_to_buf(_out_iov, _out_niov, 0, &hdr, sizeof(hdr)) !=
            sizeof(hdr)) {
        rawstd_error("virtio-blk request outhdr too short\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstd_iovec_discard_front(&_out_iov, &_out_niov, sizeof(hdr));

    if (_in_niov == 0 ||
        _in_iov[_in_niov - 1].iov_len < sizeof(unsigned char)) {
        rawstd_error("virtio-blk request status footer too short\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    _status = reinterpret_cast<unsigned char*>(
        static_cast<char*>(_in_iov[_in_niov - 1].iov_base) +
        _in_iov[_in_niov - 1].iov_len - sizeof(unsigned char)
    );

    rawstd_iovec_discard_back(&_in_iov, &_in_niov, sizeof(unsigned char));

    _type = RAWSTD_LE32TOH(hdr.type) & ~(uint32_t)VIRTIO_BLK_T_BARRIER;
    _offset = RAWSTD_LE64TOH(hdr.sector) << VIRTIO_BLK_SECTOR_BITS;
}

} // namespace vduse
} // namespace rawstor
