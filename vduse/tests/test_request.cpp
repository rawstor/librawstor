#include <gtest/gtest.h>

#include <vduse/request.hpp>

#include <stdheaders/linux/virtio_blk.h>

#include <sys/uio.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <system_error>

using rawstor::vduse::BlkRequest;

namespace {

virtio_blk_outhdr make_hdr(uint32_t type, uint64_t sector) {
    virtio_blk_outhdr hdr = {};
    hdr.type = type;
    hdr.ioprio = 0;
    hdr.sector = sector;
    return hdr;
}

} // namespace

TEST(BlkRequestTest, ReadRequestDecodesTypeAndOffset) {
    virtio_blk_outhdr hdr = make_hdr(VIRTIO_BLK_T_IN, 16);

    iovec out_iov[] = {{&hdr, sizeof(hdr)}};

    std::array<char, 512> payload = {};
    unsigned char status = 0xff;
    iovec in_iov[] = {{payload.data(), payload.size()}, {&status, 1}};

    BlkRequest req(out_iov, 1, in_iov, 2);

    EXPECT_EQ(req.type(), (uint32_t)VIRTIO_BLK_T_IN);
    EXPECT_EQ(req.offset(), 16u << 9);

    ASSERT_EQ(req.out_niov(), 0u);

    ASSERT_EQ(req.in_niov(), 1u);
    EXPECT_EQ(req.in_iov()[0].iov_base, payload.data());
    EXPECT_EQ(req.in_iov()[0].iov_len, payload.size());

    req.set_status(0);
    EXPECT_EQ(status, 0);
}

TEST(BlkRequestTest, WriteRequestDecodesTypeAndOffset) {
    virtio_blk_outhdr hdr = make_hdr(VIRTIO_BLK_T_OUT, 32);

    std::array<char, 512> payload = {};
    iovec out_iov[] = {{&hdr, sizeof(hdr)}, {payload.data(), payload.size()}};

    unsigned char status = 0xff;
    iovec in_iov[] = {{&status, 1}};

    BlkRequest req(out_iov, 2, in_iov, 1);

    EXPECT_EQ(req.type(), (uint32_t)VIRTIO_BLK_T_OUT);
    EXPECT_EQ(req.offset(), 32u << 9);

    ASSERT_EQ(req.out_niov(), 1u);
    EXPECT_EQ(req.out_iov()[0].iov_base, payload.data());
    EXPECT_EQ(req.out_iov()[0].iov_len, payload.size());

    ASSERT_EQ(req.in_niov(), 0u);

    req.set_status(VIRTIO_BLK_S_OK);
    EXPECT_EQ(status, VIRTIO_BLK_S_OK);
}

TEST(BlkRequestTest, BarrierBitIsMaskedOffType) {
    virtio_blk_outhdr hdr =
        make_hdr(VIRTIO_BLK_T_OUT | VIRTIO_BLK_T_BARRIER, 0);

    iovec out_iov[] = {{&hdr, sizeof(hdr)}};
    unsigned char status = 0;
    iovec in_iov[] = {{&status, 1}};

    BlkRequest req(out_iov, 1, in_iov, 1);

    EXPECT_EQ(req.type(), (uint32_t)VIRTIO_BLK_T_OUT);
}

TEST(BlkRequestTest, TooShortHeaderThrows) {
    char small[4] = {};
    iovec out_iov[] = {{small, sizeof(small)}};
    unsigned char status = 0;
    iovec in_iov[] = {{&status, 1}};

    EXPECT_THROW(BlkRequest(out_iov, 1, in_iov, 1), std::system_error);
}

TEST(BlkRequestTest, EmptyOutIovThrows) {
    unsigned char status = 0;
    iovec in_iov[] = {{&status, 1}};

    EXPECT_THROW(BlkRequest(nullptr, 0, in_iov, 1), std::system_error);
}

TEST(BlkRequestTest, EmptyInIovThrows) {
    virtio_blk_outhdr hdr = make_hdr(VIRTIO_BLK_T_OUT, 0);
    iovec out_iov[] = {{&hdr, sizeof(hdr)}};

    EXPECT_THROW(BlkRequest(out_iov, 1, nullptr, 0), std::system_error);
}
