// Volume::snapshot()/snap_remove() (rawstor_docs/Mds.md, "Snapshots
// (stage 2)"), exercised against a real rawstor::mds::Server +
// rawstor::ostserver::Server pair (volume_env.hpp) -- the actual wire
// path a `mds://` target goes through, not a hand-scripted mock of it.
// The OST's only backend is file://, which has no native CoW, so every
// case here is a negative-path/error-propagation test: the positive CoW
// path needs a live zfs pool and isn't reachable from a portable test
// (see volume_env.hpp's own doc comment).
#include "rawio_sync.hpp"
#include "volume_env.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>

#include <cerrno>

namespace {

ssize_t target_create(
    rawio::Queue& queue, const std::string& target,
    const RawstorObjectSpec& spec
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_create(&queue, target.c_str(), &spec, cb, data);
    });
}

ssize_t target_spec(
    rawio::Queue& queue, const std::string& target, RawstorObjectSpec* spec
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_spec(&queue, target.c_str(), spec, cb, data);
    });
}

ssize_t target_remove(rawio::Queue& queue, const std::string& target) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_remove(&queue, target.c_str(), cb, data);
    });
}

ssize_t volume_snapshot(
    rawio::Queue& queue, const std::string& target, uint64_t* snap_id
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_volume_snapshot(
            &queue, target.c_str(), snap_id, cb, data
        );
    });
}

ssize_t volume_snap_remove(
    rawio::Queue& queue, const std::string& target, uint64_t snap_id
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_volume_snap_remove(
            &queue, target.c_str(), snap_id, cb, data
        );
    });
}

ssize_t volume_resize(
    rawio::Queue& queue, const std::string& target, uint64_t new_size
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_volume_resize(
            &queue, target.c_str(), new_size, cb, data
        );
    });
}

std::string
volume_target(const rawstor::tests::VolumeEnv& env, const char* uuid) {
    rawstd::URI location_uri(env.location());
    return rawstd::URI(location_uri, uuid).str();
}

RawstorObjectSpec one_chunk_spec() {
    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.mirrors = 1;
    return spec;
}

} // namespace

// A volume backed by a file:// chunk member has no native CoW -- the
// snapshot attempt reaches the real OST, gets a real -ENOTSUP from
// file::Backend::snapshot(), and Volume::snapshot() surfaces that
// specific error (not a generic failure) since the chunk had exactly
// one member and it's the one that failed.
TEST(VolumeSnapshotTest, snapshot_on_file_backend_returns_enotsup) {
    rawstor::tests::VolumeEnv env(8770, 8771);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000001");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    uint64_t snap_id = 0;
    ssize_t res = volume_snapshot(*queue, target, &snap_id);
    EXPECT_EQ(res, -ENOTSUP);
    EXPECT_EQ(snap_id, 0u);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// A snapshot attempt that never reaches VOL_SNAP_COMMIT (every chunk
// member failed the backend CoW) must leave the volume exactly as
// before -- spec() still answers normally, the failed attempt left no
// visible trace on the live map.
TEST(VolumeSnapshotTest, failed_snapshot_leaves_volume_intact) {
    rawstor::tests::VolumeEnv env(8772, 8773);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000002");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    uint64_t snap_id = 0;
    ASSERT_EQ(volume_snapshot(*queue, target, &snap_id), -ENOTSUP);

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, spec.size);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// vol_snap_remove() on an id nothing ever committed fails cleanly with
// -ENOENT (the MDS's own rejection), not a hang or a crash -- this is
// the same case a crash between VOL_SNAP_BEGIN and VOL_SNAP_COMMIT
// leaves behind (rawstor_docs/Mds.md: reconciled by the reconstruct
// scan, never by snap_remove()).
TEST(VolumeSnapshotTest, snap_remove_uncommitted_returns_enoent) {
    rawstor::tests::VolumeEnv env(8774, 8775);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000003");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(volume_snap_remove(*queue, target, 999), -ENOENT);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// snap_id 0 means "live" everywhere on the wire (rawstor_docs/Mds.md,
// "version in chunk identity") -- Volume::snap_remove() rejects it
// before any network round trip.
TEST(VolumeSnapshotTest, snap_remove_zero_is_einval) {
    rawstor::tests::VolumeEnv env(8776, 8777);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000004");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(volume_snap_remove(*queue, target, 0), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// Neither call makes sense against a plain (non-"mds://") target -- no
// MDS to reserve/register a snap_id with -- and both must reject it
// immediately rather than trying rawstor_target_snapshot()'s own
// caller-supplied-id semantics.
TEST(VolumeSnapshotTest, non_volume_target_is_einval) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    const char* target = "ost://127.0.0.1:1/018f4e2a-3000-7000-8000-"
                         "000000000005";

    uint64_t snap_id = 0;
    EXPECT_EQ(volume_snapshot(*queue, target, &snap_id), -EINVAL);
    EXPECT_EQ(volume_snap_remove(*queue, target, 1), -EINVAL);
}

// Growing a multi-chunk volume reserves placement for the new chunks on
// the MDS and materializes exactly those on the OST -- spec() reflects
// the new size, and the volume stays fully readable/writable across the
// old/new chunk boundary afterward.
TEST(VolumeResizeTest, grows_and_creates_new_chunks) {
    rawstor::tests::VolumeEnv env(8778, 8779);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000006");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec{};
    spec.size = 512ull << 10; /* 512 KiB, one chunk */
    spec.mirrors = 1;
    spec.chunk_size = 512ull << 10;
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    ASSERT_EQ(volume_resize(*queue, target, 2ull << 20 /* 2 MiB */), 0);

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, 2ull << 20);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// Grow-only: the MDS itself rejects a smaller new_size.
TEST(VolumeResizeTest, shrink_is_einval) {
    rawstor::tests::VolumeEnv env(8780, 8781);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000007");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(volume_resize(*queue, target, spec.size / 2), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// new_size 0 is rejected client-side before any round trip.
TEST(VolumeResizeTest, zero_is_einval) {
    rawstor::tests::VolumeEnv env(8782, 8783);
    std::string target =
        volume_target(env, "018f4e2a-3000-7000-8000-000000000008");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(volume_resize(*queue, target, 0), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// resize() makes no sense against a plain (non-"mds://") target -- no
// MDS to reserve placement with.
TEST(VolumeResizeTest, non_volume_target_is_einval) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    const char* target = "ost://127.0.0.1:1/018f4e2a-3000-7000-8000-"
                         "000000000009";

    EXPECT_EQ(volume_resize(*queue, target, 1ull << 20), -EINVAL);
}
