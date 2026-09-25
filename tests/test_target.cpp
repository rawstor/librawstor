#include "target.hpp"

#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <string>
#include <system_error>

namespace {

const std::string id_str = "019cbfad-a389-7d42-a0f6-c29993ac8c00";
const std::string snap_str = "019cbfad-a389-7d42-a0f6-c29993ac8c01";

// Not gtest-EXPECT-checked: called during static initialization, before
// any test body runs, so gtest's own assertion machinery isn't set up
// yet -- id_str/snap_str are well-formed UUID literals, so this can't
// fail in practice.
RawstdUUID uuid_of(const std::string& s) {
    RawstdUUID ret;
    rawstd_uuid_from_string(&ret, s.c_str());
    return ret;
}

const RawstdUUID id_uuid = uuid_of(id_str);
const RawstdUUID snap_uuid = uuid_of(snap_str);

} // namespace

TEST(TargetParsePathTest, bare_id_has_no_offset_or_snapshot) {
    rawstor::TargetPath path = rawstor::parse_target_path("/data/" + id_str);

    EXPECT_EQ(rawstd_uuid_cmp(&path.id, &id_uuid), 0);
    EXPECT_EQ(path.offset, 0u);
    EXPECT_TRUE(rawstd_uuid_is_nil(&path.snapshot_id));
    EXPECT_EQ(path.segments, 1u);
}

TEST(TargetParsePathTest, physical_live_shape_has_offset_no_snapshot) {
    rawstor::TargetPath path =
        rawstor::parse_target_path("/data/" + id_str + "/2a");

    EXPECT_EQ(rawstd_uuid_cmp(&path.id, &id_uuid), 0);
    EXPECT_EQ(path.offset, 42u);
    EXPECT_TRUE(rawstd_uuid_is_nil(&path.snapshot_id));
    EXPECT_EQ(path.segments, 2u);
}

TEST(TargetParsePathTest, logical_shape_has_snapshot_no_offset) {
    rawstor::TargetPath path =
        rawstor::parse_target_path("/data/" + id_str + "/" + snap_str);

    EXPECT_EQ(rawstd_uuid_cmp(&path.id, &id_uuid), 0);
    EXPECT_EQ(path.offset, 0u);
    EXPECT_EQ(rawstd_uuid_cmp(&path.snapshot_id, &snap_uuid), 0);
    EXPECT_EQ(path.segments, 2u);
}

TEST(TargetParsePathTest, physical_shape_with_snapshot_has_both) {
    rawstor::TargetPath path =
        rawstor::parse_target_path("/data/" + id_str + "/2a/" + snap_str);

    EXPECT_EQ(rawstd_uuid_cmp(&path.id, &id_uuid), 0);
    EXPECT_EQ(path.offset, 42u);
    EXPECT_EQ(rawstd_uuid_cmp(&path.snapshot_id, &snap_uuid), 0);
    EXPECT_EQ(path.segments, 3u);
}

TEST(TargetParsePathTest, deep_location_prefix_does_not_confuse_parsing) {
    rawstor::TargetPath path =
        rawstor::parse_target_path("/a/b/c/" + id_str + "/2a/" + snap_str);

    EXPECT_EQ(rawstd_uuid_cmp(&path.id, &id_uuid), 0);
    EXPECT_EQ(path.offset, 42u);
    EXPECT_EQ(rawstd_uuid_cmp(&path.snapshot_id, &snap_uuid), 0);
    EXPECT_EQ(path.segments, 3u);
}

TEST(TargetParsePathTest, malformed_path_throws_einval) {
    EXPECT_THROW(
        rawstor::parse_target_path("/data/not-a-uuid"), std::system_error
    );
}
