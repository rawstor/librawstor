#include <stdheaders/linux/virtio_ring.h>
#include <vduse/ring.hpp>
#include <vduse/virtqueue.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using rawstor::vduse::AddressTranslator;
using rawstor::vduse::DescChain;
using rawstor::vduse::inflight_region_size;
using rawstor::vduse::InflightRegion;
using rawstor::vduse::VirtQueue;

constexpr unsigned int kQueueSize = 8;

AddressTranslator IdentityTranslator() {
    return [](uint64_t addr) { return reinterpret_cast<void*>(addr); };
}

/**
 * Raw "guest memory" for a single virtqueue: a descriptor table plus avail
 * and used rings, each with the extra trailing slot VIRTIO_RING_F_EVENT_IDX
 * needs. IOVAs in these tests are just host pointer values, translated by
 * the identity AddressTranslator above. Mirrors vhost/tests'.
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
        vq.set_vring_addr(
            IdentityTranslator(), reinterpret_cast<uint64_t>(mem.descs.data()),
            reinterpret_cast<uint64_t>(mem.avail),
            reinterpret_cast<uint64_t>(mem.used)
        );
    }
};

/**
 * In-flight log memory for a single virtqueue, sized like the real
 * thing (InflightRegion header plus one InflightDesc per head).
 */
class FakeInflightLog {
public:
    std::vector<uint64_t> storage;
    InflightRegion* region;

    explicit FakeInflightLog(uint16_t desc_num) :
        storage(inflight_region_size(desc_num) / sizeof(uint64_t), 0) {
        region = reinterpret_cast<InflightRegion*>(storage.data());
        region->desc_num = desc_num;
    }
};

class VirtQueueInflightTest : public VirtQueueTest {
protected:
    uint8_t buf[4] = {};

    void SetUp() override {
        VirtQueueTest::SetUp();
        for (unsigned int i = 0; i < kQueueSize; ++i) {
            mem.set_desc(i, buf, sizeof(buf), VRING_DESC_F_WRITE);
        }
    }
};

TEST_F(VirtQueueInflightTest, FreshLogIsInitializedAndBaseKept) {
    // Everything the driver queued was already consumed.
    mem.publish_avail(0);
    mem.publish_avail(1);
    mem.publish_avail(2);
    FakeInflightLog log(kQueueSize);
    vq.set_vring_base(3);
    vq.set_inflight(log.region);

    EXPECT_EQ(vq.pop(IdentityTranslator()), nullptr);
    EXPECT_EQ(log.region->version, 1);
    EXPECT_EQ(vq.last_avail_idx(), 3);
}

TEST_F(VirtQueueInflightTest, PopMarksHeadAndPushClearsIt) {
    FakeInflightLog log(kQueueSize);
    vq.set_inflight(log.region);

    mem.publish_avail(2);
    mem.publish_avail(5);
    std::unique_ptr<DescChain> a = vq.pop(IdentityTranslator());
    std::unique_ptr<DescChain> b = vq.pop(IdentityTranslator());
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);

    EXPECT_EQ(log.region->desc[2].inflight, 1);
    EXPECT_EQ(log.region->desc[5].inflight, 1);
    EXPECT_LT(log.region->desc[2].counter, log.region->desc[5].counter);

    vq.push(5, 0);
    EXPECT_EQ(log.region->desc[2].inflight, 1);
    EXPECT_EQ(log.region->desc[5].inflight, 0);
    EXPECT_EQ(log.region->last_batch_head, 5);
    EXPECT_EQ(log.region->used_idx, 1);
}

TEST_F(VirtQueueInflightTest, ResubmitsInFlightHeadsInPopOrderFirst) {
    // A previous instance popped heads 6, 1, 4 (in that order) and only
    // completed 1, out of order; the driver has since queued head 3.
    mem.publish_avail(6);
    mem.publish_avail(1);
    mem.publish_avail(4);
    mem.publish_avail(3);
    mem.used->idx = 1;

    FakeInflightLog log(kQueueSize);
    log.region->version = 1;
    log.region->used_idx = 1;
    log.region->desc[6] = {1, {}, 0, 10};
    log.region->desc[4] = {1, {}, 0, 12};

    vq.set_inflight(log.region);

    std::unique_ptr<DescChain> chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 6);
    chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 4);

    // used->idx (1) plus the two still in flight.
    EXPECT_EQ(vq.last_avail_idx(), 3);
    chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 3);
    EXPECT_GT(log.region->desc[3].counter, log.region->desc[4].counter);

    EXPECT_EQ(vq.pop(IdentityTranslator()), nullptr);

    // Completions land after the used entry already there.
    vq.push(4, 0);
    EXPECT_EQ(mem.used->idx, 2);
    EXPECT_EQ(mem.used->ring[1].id, 4u);
}

TEST_F(VirtQueueInflightTest, ClearsLastBatchHeadPublishedButNotRecorded) {
    // Died right after publishing used->idx for head 2, before clearing
    // its in-flight mark.
    mem.publish_avail(2);
    mem.used->idx = 1;
    mem.used->ring[0].id = 2;

    FakeInflightLog log(kQueueSize);
    log.region->version = 1;
    log.region->used_idx = 0;
    log.region->last_batch_head = 2;
    log.region->desc[2] = {1, {}, 0, 0};

    vq.set_inflight(log.region);

    EXPECT_EQ(vq.pop(IdentityTranslator()), nullptr);
    EXPECT_EQ(log.region->desc[2].inflight, 0);
    EXPECT_EQ(log.region->used_idx, 1);
    EXPECT_EQ(vq.last_avail_idx(), 1);
}

TEST_F(VirtQueueInflightTest, LogSmallerThanRingIsIgnored) {
    FakeInflightLog log(kQueueSize / 2);
    vq.set_inflight(log.region);

    mem.publish_avail(7);
    std::unique_ptr<DescChain> chain = vq.pop(IdentityTranslator());
    ASSERT_NE(chain, nullptr);
    EXPECT_EQ(chain->head, 7);
    EXPECT_EQ(log.region->version, 0);
}

} // namespace
