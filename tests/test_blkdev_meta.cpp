#include "blkdev_meta.hpp"

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <string>

namespace {

TEST(BlkdevMetaTest, encode_decode_round_trip) {
    RawstorObjectMeta meta{};
    meta.size = 12345; /* ignored by encode/decode: identity fields only */
    meta.state = RAWSTOR_OBJECT_STATE_DIRTY;
    meta.epoch = 7;
    meta.sync_id = 0x1122334455667788ull;
    meta.sync_id_history[0] = 0xaabbccddeeff0011ull;
    meta.sync_id_history[1] = 1;
    meta.sync_id_history[2] = 2;
    meta.sync_id_history[3] = 3;

    std::string encoded = rawstor::blkdev_meta_encode(meta);

    RawstorObjectMeta decoded{};
    ASSERT_TRUE(rawstor::blkdev_meta_decode(encoded, &decoded));
    EXPECT_EQ(decoded.state, meta.state);
    EXPECT_EQ(decoded.epoch, meta.epoch);
    EXPECT_EQ(decoded.sync_id, meta.sync_id);
    EXPECT_EQ(decoded.sync_id_history[0], meta.sync_id_history[0]);
    EXPECT_EQ(decoded.sync_id_history[1], meta.sync_id_history[1]);
    EXPECT_EQ(decoded.sync_id_history[2], meta.sync_id_history[2]);
    EXPECT_EQ(decoded.sync_id_history[3], meta.sync_id_history[3]);
}

TEST(BlkdevMetaTest, decode_rejects_empty_string) {
    /* A missing property/tag must never be mistaken for a valid record. */
    RawstorObjectMeta decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("", &decoded));
}

TEST(BlkdevMetaTest, decode_rejects_zfs_unset_marker) {
    RawstorObjectMeta decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("-", &decoded));
}

TEST(BlkdevMetaTest, decode_rejects_malformed_string) {
    RawstorObjectMeta decoded{};
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
