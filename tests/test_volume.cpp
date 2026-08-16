#include "volume.hpp"

#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <cstring>

namespace {

using rawstor::volume_chunk_uuid;
using rawstor::volume_segments;
using rawstor::VolumeSegment;

TEST(VolumeSegmentsTest, single_chunk_passthrough) {
    std::vector<VolumeSegment> s = volume_segments(4096, 512, 1 << 20);
    ASSERT_EQ(s.size(), 1u);
    EXPECT_EQ(s[0].index, 0u);
    EXPECT_EQ(s[0].chunk_offset, 4096);
    EXPECT_EQ(s[0].size, 512u);
    EXPECT_EQ(s[0].buf_offset, 0u);
}

TEST(VolumeSegmentsTest, split_at_boundary) {
    /* 8 KiB starting 4 KiB before a 1 MiB boundary. */
    std::vector<VolumeSegment> s =
        volume_segments((1 << 20) - 4096, 8192, 1 << 20);
    ASSERT_EQ(s.size(), 2u);

    EXPECT_EQ(s[0].index, 0u);
    EXPECT_EQ(s[0].chunk_offset, (1 << 20) - 4096);
    EXPECT_EQ(s[0].size, 4096u);
    EXPECT_EQ(s[0].buf_offset, 0u);

    EXPECT_EQ(s[1].index, 1u);
    EXPECT_EQ(s[1].chunk_offset, 0);
    EXPECT_EQ(s[1].size, 4096u);
    EXPECT_EQ(s[1].buf_offset, 4096u);
}

TEST(VolumeSegmentsTest, spans_whole_chunks) {
    /* 3 MiB + 1 byte from offset 1 MiB - 1: 1 + 3 + tail. */
    std::vector<VolumeSegment> s =
        volume_segments((1 << 20) - 1, (3u << 20) + 2, 1 << 20);
    ASSERT_EQ(s.size(), 5u);
    EXPECT_EQ(s[0].size, 1u);
    EXPECT_EQ(s[1].size, 1u << 20);
    EXPECT_EQ(s[2].size, 1u << 20);
    EXPECT_EQ(s[3].size, 1u << 20);
    EXPECT_EQ(s[4].size, 1u);
    EXPECT_EQ(s[4].index, 4u);

    size_t total = 0;
    for (const VolumeSegment& segment : s) {
        EXPECT_EQ(segment.buf_offset, total);
        total += segment.size;
    }
    EXPECT_EQ(total, (3u << 20) + 2);
}

TEST(VolumeChunkUuidTest, index_zero_is_identity) {
    RawstdUUID vol;
    ASSERT_EQ(
        rawstd_uuid_from_string(&vol, "11111111-2222-7333-8444-555566667777"), 0
    );

    RawstdUUID chunk0 = volume_chunk_uuid(vol, 0);
    EXPECT_EQ(memcmp(chunk0.bytes, vol.bytes, sizeof(vol.bytes)), 0);

    RawstdUUID chunk1 = volume_chunk_uuid(vol, 1);
    EXPECT_NE(memcmp(chunk1.bytes, vol.bytes, sizeof(vol.bytes)), 0);

    /* Deterministic and invertible (XOR). */
    RawstdUUID again = volume_chunk_uuid(chunk1, 1);
    EXPECT_EQ(memcmp(again.bytes, vol.bytes, sizeof(vol.bytes)), 0);
}

} // unnamed namespace
