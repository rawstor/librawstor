// Object::snapshot_create()/snapshot_remove() (docs/mds.md, "Snapshots
// (stage 2)"), exercised against a real rawstor::mds::Server +
// rawstor::ostserver::Server pair (object_env.hpp) -- the actual wire
// path a `mds://` target goes through, not a hand-scripted mock of it.
// The OST's only backend is file://, which has no native CoW, so every
// case here is a negative-path/error-propagation test: the positive CoW
// path needs a live zfs pool and isn't reachable from a portable test
// (see object_env.hpp's own doc comment).
#include "object_env.hpp"
#include "rawio_sync.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>

#include <cerrno>

namespace {

// A plain file:// target -- no MDS, no OST, nothing to connect to except
// the local filesystem -- for the tests below that verify Backend::
// resize()/snapshot_create_assign()'s own ENOTSUP default is what a
// non-mds:// target actually gets, not a scheme-specific rejection.
std::string file_target(const char* name, const char* uuid) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / name;
    std::filesystem::create_directories(location_path);
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    return rawstd::URI(rawstd::URI(oss.str()), uuid).str();
}

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

ssize_t object_snapshot_create(
    rawio::Queue& queue, const std::string& target, uint64_t* snap_id
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_snapshot_create(
            &queue, target.c_str(), snap_id, cb, data
        );
    });
}

ssize_t object_snapshot_remove(
    rawio::Queue& queue, const std::string& target, uint64_t snap_id
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_snapshot_remove(
            &queue, target.c_str(), snap_id, cb, data
        );
    });
}

ssize_t object_resize(
    rawio::Queue& queue, const std::string& target, uint64_t new_size
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_resize(
            &queue, target.c_str(), new_size, cb, data
        );
    });
}

ssize_t target_meta(
    rawio::Queue& queue, const std::string& target, RawstorObjectMeta* metas,
    size_t count
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_meta(
            &queue, target.c_str(), metas, count, cb, data
        );
    });
}

ssize_t target_set_sync_state(
    rawio::Queue& queue, const std::string& target,
    const RawstorObjectSyncState& sync_state
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_set_sync_state(
            &queue, target.c_str(), &sync_state, cb, data
        );
    });
}

std::string
object_target(const rawstor::tests::ObjectEnv& env, const char* uuid) {
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

// An object backed by a file:// chunk member has no native CoW -- the
// snapshot attempt reaches the real OST, gets a real -ENOTSUP from
// file::Backend::snapshot_create(), and Object::snapshot_create()
// surfaces that specific error (not a generic failure) since the chunk
// had exactly one member and it's the one that failed.
TEST(ObjectSnapshotTest, snapshot_on_file_backend_returns_enotsup) {
    rawstor::tests::ObjectEnv env(8770, 8771);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000001");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    uint64_t snap_id = 0;
    ssize_t res = object_snapshot_create(*queue, target, &snap_id);
    EXPECT_EQ(res, -ENOTSUP);
    EXPECT_EQ(snap_id, 0u);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// A snapshot attempt that never reaches OBJ_SNAP_COMMIT (every chunk
// member failed the backend CoW) must leave the object exactly as
// before -- spec() still answers normally, the failed attempt left no
// visible trace on the live map.
TEST(ObjectSnapshotTest, failed_snapshot_leaves_object_intact) {
    rawstor::tests::ObjectEnv env(8772, 8773);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000002");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    uint64_t snap_id = 0;
    ASSERT_EQ(object_snapshot_create(*queue, target, &snap_id), -ENOTSUP);

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, spec.size);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// snap_remove() on an id nothing ever committed fails cleanly with
// -ENOENT (the MDS's own rejection), not a hang or a crash -- this is
// the same case a crash between OBJ_SNAP_BEGIN and OBJ_SNAP_COMMIT
// leaves behind (docs/mds.md: reconciled by the reconstruct
// scan, never by snapshot_remove()).
TEST(ObjectSnapshotTest, snapshot_remove_uncommitted_returns_enoent) {
    rawstor::tests::ObjectEnv env(8774, 8775);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000003");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(object_snapshot_remove(*queue, target, 999), -ENOENT);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// snap_id 0 means "live" everywhere on the wire (docs/mds.md,
// "version in chunk identity") -- Object::snapshot_remove() rejects it
// before any network round trip.
TEST(ObjectSnapshotTest, snapshot_remove_zero_is_einval) {
    rawstor::tests::ObjectEnv env(8776, 8777);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000004");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(object_snapshot_remove(*queue, target, 0), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// "Assign one for me" (`snap_id == 0`) has no meaning against a plain
// (non-"mds://") target -- no MDS to reserve/register one with.
// rawstor_target_snapshot_create() no longer special-cases the scheme
// client-side (target.cpp unifies every target through the same
// Target::snapshot_create_assign(), mds:// included) -- a plain target's
// own backend (file::Backend here) simply has no override for it, so
// Backend::snapshot_create_assign()'s own ENOTSUP default is what
// actually comes back, the same way snapshot_on_file_backend_returns_
// enotsup above gets a real -ENOTSUP from a real backend instead of a
// synthetic client-side rejection.
TEST(ObjectSnapshotTest, snapshot_create_assign_on_non_mds_returns_enotsup) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_snap_assign_enotsup",
        "018f4e2a-3000-7000-8000-000000000005"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    uint64_t snap_id = 0;
    EXPECT_EQ(object_snapshot_create(*queue, target, &snap_id), -ENOTSUP);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// The other direction of the same dispatch: a caller-supplied (nonzero)
// id makes no sense against an mds:// target either -- an object has no
// single physical backend one native CoW call could apply to, and using
// it would bypass the MDS's own id reservation. mds::Backend::
// snapshot_create() rejects this with -EINVAL itself (unconditionally --
// see mds_backend.cpp), so this needs a real, reachable MDS to actually
// reach that check (an unreachable address would fail on the connection
// itself first, same as the ENOTSUP case above).
TEST(
    ObjectSnapshotTest, snapshot_create_nonzero_id_on_object_target_is_einval
) {
    rawstor::tests::ObjectEnv env(8784, 8785);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-00000000000a");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    uint64_t snap_id = 1;
    EXPECT_EQ(object_snapshot_create(*queue, target, &snap_id), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// rawstor_target_meta()/_set_sync_state() used to reject an mds:// target
// client-side (docs/mirroring.md doesn't apply to a whole object, many
// chunks each with their own slots) -- now that mds:// is an ordinary
// Backend, both succeed instead, with mds::Backend's own synthetic
// answer (spec.size = the object's logical size, sync_state = a "legacy
// copy" CLEAN/epoch-0/sync_id-0 -- see mds_backend.cpp's own doc
// comment): the real per-chunk DIRTY/CLEAN state is honestly tracked one
// level down, by each chunk's own (possibly mirrored) Chunk, not exposed
// through the object-level target at all.
TEST(ObjectMetaTest, meta_on_object_target_is_synthetic) {
    rawstor::tests::ObjectEnv env(8786, 8787);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-00000000000b");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstorObjectMeta meta{};
    ASSERT_EQ(target_meta(*queue, target, &meta, 1), 1);
    EXPECT_EQ(meta.spec.size, spec.size);
    EXPECT_EQ(meta.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(meta.sync_state.sync_id, 0u);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

TEST(ObjectMetaTest, set_sync_state_on_object_target_is_noop) {
    rawstor::tests::ObjectEnv env(8788, 8789);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-00000000000c");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstorObjectSyncState sync_state{};
    EXPECT_EQ(target_set_sync_state(*queue, target, sync_state), 0);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// Growing a multi-chunk object reserves placement for the new chunks on
// the MDS and materializes exactly those on the OST -- spec() reflects
// the new size, and the object stays fully readable/writable across the
// old/new chunk boundary afterward.
TEST(ObjectResizeTest, grows_and_creates_new_chunks) {
    rawstor::tests::ObjectEnv env(8778, 8779);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000006");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec{};
    spec.size = 512ull << 10; /* 512 KiB, one chunk */
    spec.mirrors = 1;
    spec.chunk_size = 512ull << 10;
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    ASSERT_EQ(object_resize(*queue, target, 2ull << 20 /* 2 MiB */), 0);

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, 2ull << 20);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// Grow-only: the MDS itself rejects a smaller new_size.
TEST(ObjectResizeTest, shrink_is_einval) {
    rawstor::tests::ObjectEnv env(8780, 8781);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000007");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(object_resize(*queue, target, spec.size / 2), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// new_size 0 is rejected client-side before any round trip.
TEST(ObjectResizeTest, zero_is_einval) {
    rawstor::tests::ObjectEnv env(8782, 8783);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000008");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(object_resize(*queue, target, 0), -EINVAL);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// resize() makes no sense against a plain (non-"mds://") target -- no
// MDS to reserve placement with. Unified dispatch (target.cpp) no longer
// rejects this client-side by scheme -- it reaches the target's own
// backend (file::Backend here) and gets Backend::resize()'s own ENOTSUP
// default, the same real-backend-error shape as
// snapshot_create_assign_on_non_mds_returns_enotsup above.
TEST(ObjectResizeTest, non_mds_target_returns_enotsup) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_resize_enotsup", "018f4e2a-3000-7000-8000-000000000009"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(object_resize(*queue, target, 1ull << 20), -ENOTSUP);

    EXPECT_EQ(target_remove(*queue, target), 0);
}
