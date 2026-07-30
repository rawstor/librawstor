#include <stdheaders/linux/virtio_ring.h>
#include <vhost/ring.hpp>
#include <vhost/virtqueue.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using rawstor::vhost::AddressTranslator;
using rawstor::vhost::DescChain;
using rawstor::vhost::VirtQueue;

constexpr unsigned int kQueueSize = 8;

AddressTranslator IdentityTranslator() {
    return [](uint64_t addr) { return reinterpret_cast<void*>(addr); };
}

/**
 * Raw "guest memory" for a single virtqueue: a descriptor table plus avail
 * and used rings, each with the extra trailing slot VIRTIO_RING_F_EVENT_IDX
 * needs to carry the used_event / avail_event index. Guest addresses in
 * these tests are just host pointer values, translated by the identity
 * AddressTranslator above.
 */
class FakeQueueMemory {
public:
    std::vector<vring_desc> descs;
    std::vector<uint8_t> avail_storage;
    std::vector<uint8_t> used_storage;
    vring_avail* avail;
    vring_used* used;

    explicit FakeQueueMemory(unsigned int num) :
        descs(num),
        avail_storage(sizeof(vring_avail) + (num + 1) * sizeof(uint16_t), 0),
        used_storage(
            sizeof(vring_used) + (num + 1) * sizeof(vring_used_elem_t), 0
        ) {
        avail = reinterpret_cast<vring_avail*>(avail_storage.data());
        used = reinterpret_cast<vring_used*>(used_storage.data());
    }

    vhost_vring_addr addr() const {
        vhost_vring_addr vra{};
        vra.index = 0;
        vra.flags = 0;
        vra.desc_user_addr =
            reinterpret_cast<uint64_t>(const_cast<vring_desc*>(descs.data()));
        vra.avail_user_addr = reinterpret_cast<uint64_t>(avail);
        vra.used_user_addr = reinterpret_cast<uint64_t>(used);
        vra.log_guest_addr = 0;
        return vra;
    }

    void set_desc(
        unsigned int idx, const void* buf, uint32_t len, uint16_t flags,
        uint16_t next = 0
    ) {
        descs[idx].addr = reinterpret_cast<uint64_t>(buf);
        descs[idx].len = len;
        descs[idx].flags = flags;
        descs[idx].next = next;
    }

    void publish_avail(uint16_t head) {
        unsigned int slot = avail->idx % descs.size();
        avail->ring[slot] = head;
        avail->idx = static_cast<uint16_t>(avail->idx + 1);
    }
};

class VirtQueueTest : public ::testing::Test {
protected:
    FakeQueueMemory mem{kQueueSize};
    VirtQueue vq;

    void SetUp() override {
        vq.set_vring_size(kQueueSize);
        vq.set_vring_addr(IdentityTranslator(), mem.addr());
    }
};

TEST_F(VirtQueueTest, PopReturnsNullWhenNothingAvailable) {
    EXPECT_EQ(vq.pop(IdentityTranslator()), nullptr);
}

TEST_F(VirtQueueTest, PopsChainedReadableThenWritableDescriptor) {
    uint8_t out_buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t in_buf[4] = {};

    mem.set_desc(0, out_buf, sizeof(out_buf), VRING_DESC_F_NEXT, 1);
    mem.set_desc(1, in_buf, sizeof(in_buf), VRING_DESC_F_WRITE);
    mem.publish_avail(0);

    std::unique_ptr<DescChain> chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 0);

    ASSERT_EQ(chain->readable.size(), 1u);
    EXPECT_EQ(chain->readable[0].iov_base, out_buf);
    EXPECT_EQ(chain->readable[0].iov_len, sizeof(out_buf));

    ASSERT_EQ(chain->writable.size(), 1u);
    EXPECT_EQ(chain->writable[0].iov_base, in_buf);
    EXPECT_EQ(chain->writable[0].iov_len, sizeof(in_buf));

    EXPECT_EQ(vq.pop(IdentityTranslator()), nullptr);
}

TEST_F(VirtQueueTest, PopsMultipleChainsInFifoOrder) {
    uint8_t buf_a[4] = {};
    uint8_t buf_b[4] = {};

    mem.set_desc(2, buf_a, sizeof(buf_a), VRING_DESC_F_WRITE);
    mem.set_desc(5, buf_b, sizeof(buf_b), VRING_DESC_F_WRITE);
    mem.publish_avail(2);
    mem.publish_avail(5);

    std::unique_ptr<DescChain> first = vq.pop(IdentityTranslator());
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->head, 2);

    std::unique_ptr<DescChain> second = vq.pop(IdentityTranslator());
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(second->head, 5);

    EXPECT_EQ(vq.pop(IdentityTranslator()), nullptr);
}

TEST_F(VirtQueueTest, PopFollowsIndirectDescriptorTable) {
    std::vector<vring_desc> indirect(2);
    uint8_t out_buf[3] = {9, 9, 9};
    uint8_t in_buf[2] = {};

    indirect[0].addr = reinterpret_cast<uint64_t>(out_buf);
    indirect[0].len = sizeof(out_buf);
    indirect[0].flags = VRING_DESC_F_NEXT;
    indirect[0].next = 1;

    indirect[1].addr = reinterpret_cast<uint64_t>(in_buf);
    indirect[1].len = sizeof(in_buf);
    indirect[1].flags = VRING_DESC_F_WRITE;
    indirect[1].next = 0;

    mem.set_desc(
        0, indirect.data(), sizeof(vring_desc) * indirect.size(),
        VRING_DESC_F_INDIRECT
    );
    mem.publish_avail(0);

    std::unique_ptr<DescChain> chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 0);
    ASSERT_EQ(chain->readable.size(), 1u);
    EXPECT_EQ(chain->readable[0].iov_base, out_buf);
    ASSERT_EQ(chain->writable.size(), 1u);
    EXPECT_EQ(chain->writable[0].iov_base, in_buf);
}

TEST_F(VirtQueueTest, PopThrowsOnCyclicChain) {
    uint8_t buf[1] = {};

    // A chain that loops back on itself must not hang forever.
    mem.set_desc(0, buf, sizeof(buf), VRING_DESC_F_NEXT, 1);
    mem.set_desc(1, buf, sizeof(buf), VRING_DESC_F_NEXT, 0);
    mem.publish_avail(0);

    EXPECT_THROW(vq.pop(IdentityTranslator()), std::runtime_error);
}

TEST_F(VirtQueueTest, PopThrowsOnUntranslatableAddress) {
    mem.set_desc(0, reinterpret_cast<void*>(0xdead), 4, 0);
    mem.publish_avail(0);

    AddressTranslator always_null = [](uint64_t) { return nullptr; };

    EXPECT_THROW(vq.pop(always_null), std::runtime_error);
}

TEST_F(VirtQueueTest, PushPublishesUsedRingEntryAndAdvancesIdx) {
    vq.push(3, 42);

    EXPECT_EQ(mem.used->idx, 1);
    EXPECT_EQ(mem.used->ring[0].id, 3u);
    EXPECT_EQ(mem.used->ring[0].len, 42u);

    vq.push(5, 7);

    EXPECT_EQ(mem.used->idx, 2);
    EXPECT_EQ(mem.used->ring[1].id, 5u);
    EXPECT_EQ(mem.used->ring[1].len, 7u);
}

TEST_F(VirtQueueTest, ShouldNotifyWithoutEventIdxRespectsNoInterruptFlag) {
    vq.push(0, 1);

    mem.avail->flags = 0;
    EXPECT_TRUE(vq.should_notify(false));

    mem.avail->flags = VRING_AVAIL_F_NO_INTERRUPT;
    EXPECT_FALSE(vq.should_notify(false));
}

TEST_F(VirtQueueTest, ShouldNotifyWithEventIdxFiresExactlyAtRequestedIndex) {
    // The first should_notify() after a (re)connect always fires,
    // regardless of used_event: the driver's used_event in this ring
    // memory isn't necessarily consistent with our freshly-adopted
    // _used_idx yet (see set_vring_addr()).
    vq.push(0, 1);
    EXPECT_TRUE(vq.should_notify(true));

    // From here on the EVENT_IDX formula actually governs. Driver is
    // waiting to be woken right after the used index reaches 2
    // (i.e. used_event == old_idx == 1).
    mem.avail->ring[kQueueSize] = 1;
    vq.push(1, 1); // old_idx=1, new_idx=2
    EXPECT_TRUE(vq.should_notify(true));
}

TEST_F(VirtQueueTest, ShouldNotifyWithEventIdxSkipsUnrelatedCompletions) {
    // Consume the guaranteed first notification so the completion below
    // is actually exercising the EVENT_IDX formula, not the
    // just-(re)connected safety net.
    vq.push(0, 1);
    EXPECT_TRUE(vq.should_notify(true));

    // Driver only wants to be woken after used index 5; this completion
    // (old_idx=1 -> new_idx=2) must not trigger a notification.
    mem.avail->ring[kQueueSize] = 4;
    vq.push(1, 1);
    EXPECT_FALSE(vq.should_notify(true));
}

TEST_F(VirtQueueTest, SetVringBaseSeedsAvailConsumerPosition) {
    vq.set_vring_base(3);
    EXPECT_EQ(vq.last_avail_idx(), 3);

    uint8_t buf[1] = {};
    mem.set_desc(0, buf, sizeof(buf), VRING_DESC_F_WRITE);

    // Place a single new entry at avail->ring[3] and set avail->idx = 4,
    // simulating a front-end that resumes queuing from index 3 (matching
    // the SET_VRING_BASE value above).
    mem.avail->ring[3 % kQueueSize] = 0;
    mem.avail->idx = 4;

    std::unique_ptr<DescChain> chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 0);
    EXPECT_EQ(vq.last_avail_idx(), 4);
}

} // namespace
