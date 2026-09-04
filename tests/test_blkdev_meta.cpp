#include "blkdev_meta.hpp"

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <string>

namespace {

TEST(BlkdevMetaTest, encode_decode_round_trip) {
    RawstorObjectSyncState sync_state{};
    sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
    sync_state.epoch = 7;
    sync_state.sync_id = 0x1122334455667788ull;
    sync_state.sync_id_history[0] = 0xaabbccddeeff0011ull;
    sync_state.sync_id_history[1] = 1;
    sync_state.sync_id_history[2] = 2;
    sync_state.sync_id_history[3] = 3;

    std::string encoded = rawstor::blkdev_meta_encode(sync_state);

    RawstorObjectSyncState decoded{};
    ASSERT_TRUE(rawstor::blkdev_meta_decode(encoded, &decoded));
    EXPECT_EQ(decoded.state, sync_state.state);
    EXPECT_EQ(decoded.epoch, sync_state.epoch);
    EXPECT_EQ(decoded.sync_id, sync_state.sync_id);
    EXPECT_EQ(decoded.sync_id_history[0], sync_state.sync_id_history[0]);
    EXPECT_EQ(decoded.sync_id_history[1], sync_state.sync_id_history[1]);
    EXPECT_EQ(decoded.sync_id_history[2], sync_state.sync_id_history[2]);
    EXPECT_EQ(decoded.sync_id_history[3], sync_state.sync_id_history[3]);
}

TEST(BlkdevMetaTest, decode_rejects_empty_string) {
    /* A missing property/tag must never be mistaken for a valid record. */
    RawstorObjectSyncState decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("", &decoded));
}

TEST(BlkdevMetaTest, decode_rejects_zfs_unset_marker) {
    RawstorObjectSyncState decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("-", &decoded));
}

TEST(BlkdevMetaTest, decode_rejects_malformed_string) {
    RawstorObjectSyncState decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("not the right format", &decoded));
}

TEST(BlkdevMetaTest, find_tag_among_multiple) {
    std::string tags = "  rawstor.meta=state=0:epoch=0,unrelated_tag  \n";
    EXPECT_EQ(
        rawstor::blkdev_find_tag(tags, "rawstor.meta="), "state=0:epoch=0"
    );
}

TEST(BlkdevMetaTest, find_tag_not_present) {
    std::string tags = "unrelated_tag,other.thing=1";
    EXPECT_EQ(rawstor::blkdev_find_tag(tags, "rawstor.meta="), "");
}

TEST(BlkdevMetaTest, find_tag_empty_list) {
    EXPECT_EQ(rawstor::blkdev_find_tag("   \n", "rawstor.meta="), "");
}

} // namespace
