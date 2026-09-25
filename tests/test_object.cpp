// mds::Backend::create_snapshot()/remove() (docs/mds.md, "Snapshots
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
#include <rawstd/uuid.h>

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
// resize()/create_snapshot()'s own ENOTSUP default is what a non-mds://
// target actually gets, not a scheme-specific rejection.
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

// Appends `snapshot_id` as a bound-snapshot path segment to `target`
// (rawstor_target_snapshot_id()'s own convention) -- the caller now
// builds this combined target itself before calling rawstor_target_
// create()/_remove(), since neither takes a separate snapshot_id
// parameter any more.
std::string
bind_snapshot_id(const std::string& target, const RawstdUUID& snapshot_id) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&snapshot_id, &uuid_string);
    return rawstd::URI(rawstd::URI(target), std::string(uuid_string)).str();
}

// `snapshot_id`: NULL to have rawstor_target_create_snapshot() itself pick
// the version id (`target`'s own bound one, or -- for a plain `target` --
// a freshly generated one), or an explicit UUID string. Either way, the
// resulting snapshot target string is written into `out_snapshot_target`,
// if given, before this returns -- same synchronous-before-any-I/O
// convention as rawstor_target_create_snapshot()'s own `snapshot_target`.
ssize_t object_create_snapshot(
    rawio::Queue& queue, const std::string& target, const char* snapshot_id,
    std::string* out_snapshot_target = nullptr
) {
    char buf[65536];
    ssize_t res = rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_create_snapshot(
            &queue, target.c_str(), snapshot_id, buf, sizeof(buf), cb, data
        );
    });
    if (out_snapshot_target != nullptr) {
        *out_snapshot_target = buf;
    }
    return res;
}

ssize_t object_remove_snapshot(
    rawio::Queue& queue, const std::string& target, const char* snapshot_id
) {
    RawstdUUID id;
    EXPECT_EQ(rawstd_uuid_from_string(&id, snapshot_id), 0);
    std::string bound_target = bind_snapshot_id(target, id);
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_remove(&queue, bound_target.c_str(), cb, data);
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
    rawio::Queue& queue, const std::string& target, uint64_t offset,
    RawstorObjectMeta* metas, size_t count
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_meta(
            &queue, target.c_str(), offset, metas, count, cb, data
        );
    });
}

ssize_t target_set_sync_state(
    rawio::Queue& queue, const std::string& target, uint64_t offset,
    const RawstorObjectSyncState& sync_state
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_set_sync_state(
            &queue, target.c_str(), offset, &sync_state, cb, data
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
    spec.width = 1;
    return spec;
}

} // namespace

// An object backed by a file:// chunk member has no native CoW -- the
// snapshot attempt reaches the real OST, gets a real -ENOTSUP from
// file::Backend::create_snapshot(), and Object::create_snapshot()
// surfaces that specific error (not a generic failure) since the chunk
// had exactly one member and it's the one that failed. `snapshot_id` is left
// NULL: the version id is generated by this very call (the single point
// every snapshot id is generated at, by analogy with a fresh object id
// -- rawstor_location_create()), spliced onto `target`, and the resulting
// target string written into `snapshot_target` synchronously, before any
// I/O -- still true even though the create itself goes on to fail.
TEST(ObjectSnapshotTest, snapshot_on_file_backend_returns_enotsup) {
    rawstor::tests::ObjectEnv env(8770, 8771);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000001");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    std::string generated_snapshot_target;
    ssize_t res = object_create_snapshot(
        *queue, target, nullptr, &generated_snapshot_target
    );
    EXPECT_EQ(res, -ENOTSUP);
    ASSERT_EQ(generated_snapshot_target.rfind(target + "/", 0), 0u);
    EXPECT_EQ(generated_snapshot_target.size(), target.size() + 1 + 36);

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

    ASSERT_EQ(object_create_snapshot(*queue, target, nullptr), -ENOTSUP);

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, spec.size);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// snap_remove() on an id nothing ever committed fails cleanly with
// -ENOENT (the MDS's own rejection), not a hang or a crash -- this is
// the same case a crash mid-fan-out (before OBJ_SNAP_COMMIT) leaves
// behind (docs/mds.md: reconciled by the reconstruct scan, never by
// remove_snapshot()).
TEST(ObjectSnapshotTest, remove_snapshot_uncommitted_returns_enoent) {
    rawstor::tests::ObjectEnv env(8774, 8775);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000003");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(
        object_remove_snapshot(
            *queue, target, "018f4e2a-3000-7000-8000-0000000000ff"
        ),
        -ENOENT
    );

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// A plain (non-"mds://") target has no MDS orchestration at all --
// create_snapshot() runs the same already-bound CoW dispatch for every
// target, mds:// included, always against a real, already-known id: a
// plain target's own backend (file::Backend here) simply has no override
// for create_snapshot(), so Backend::create_snapshot()'s own ENOTSUP
// default is what comes back, the same shape of rejection as
// snapshot_on_file_backend_returns_enotsup above, just one layer down
// (no MDS/chunk fan-out in between).
TEST(ObjectSnapshotTest, create_snapshot_on_plain_target_returns_enotsup) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_snap_assign_enotsup",
        "018f4e2a-3000-7000-8000-000000000005"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(object_create_snapshot(*queue, target, nullptr), -ENOTSUP);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// create() is only ever for a fresh object -- taking a snapshot of an
// existing one is create_snapshot()'s own job (rawstor_target_create_
// snapshot()), never create()'s.
TEST(ObjectSnapshotTest, create_on_already_bound_target_is_einval) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_create_on_bound_einval",
        "018f4e2a-3000-7000-8000-000000000014"
    );

    RawstdUUID snapshot_id;
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &snapshot_id, "018f4e2a-3000-7000-8000-000000000015"
        ),
        0
    );
    std::string bound_target = bind_snapshot_id(target, snapshot_id);

    RawstorObjectSpec spec = one_chunk_spec();
    EXPECT_EQ(target_create(*queue, bound_target, spec), -EINVAL);
}

// file:// has no native CoW (-ENOTSUP once the attempt actually reaches the
// backend), so these only exercise rawstor_target_create_snapshot()'s own
// version id resolution and resulting target string (all three modes --
// see its own doc comment, target.h) -- both are resolved and written to
// `snapshot_target` synchronously, before the doomed backend attempt, so
// that part is fully testable without a CoW-capable backend at all.
TEST(ObjectSnapshotTest, uses_id_already_bound_in_target) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_snap_bound_id", "018f4e2a-3000-7000-8000-00000000000d"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstdUUID bound_id;
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &bound_id, "018f4e2a-3000-7000-8000-00000000000e"
        ),
        0
    );
    std::string bound_target = bind_snapshot_id(target, bound_id);

    std::string used_target;
    EXPECT_EQ(
        object_create_snapshot(*queue, bound_target, nullptr, &used_target),
        -ENOTSUP
    );
    EXPECT_EQ(used_target, bound_target);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

TEST(ObjectSnapshotTest, uses_explicit_id_for_plain_target) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_snap_explicit_id", "018f4e2a-3000-7000-8000-00000000000f"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstdUUID explicit_id;
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &explicit_id, "018f4e2a-3000-7000-8000-000000000010"
        ),
        0
    );

    std::string used_target;
    EXPECT_EQ(
        object_create_snapshot(
            *queue, target, "018f4e2a-3000-7000-8000-000000000010", &used_target
        ),
        -ENOTSUP
    );
    EXPECT_EQ(used_target, bind_snapshot_id(target, explicit_id));

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// Combining an already-bound target with an explicit snapshot_id is
// ambiguous -- Target::create_snapshot(queue, id)'s own guard.
TEST(ObjectSnapshotTest, explicit_id_on_already_bound_target_is_einval) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_snap_conflict", "018f4e2a-3000-7000-8000-000000000011"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstdUUID bound_id;
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &bound_id, "018f4e2a-3000-7000-8000-000000000012"
        ),
        0
    );
    std::string bound_target = bind_snapshot_id(target, bound_id);

    EXPECT_EQ(
        object_create_snapshot(
            *queue, bound_target, "018f4e2a-3000-7000-8000-000000000013"
        ),
        -EINVAL
    );

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
    ASSERT_EQ(target_meta(*queue, target, 0, &meta, 1), 1);
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
    EXPECT_EQ(target_set_sync_state(*queue, target, 0, sync_state), 0);

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
    spec.width = 1;
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
// create_snapshot_on_plain_target_returns_enotsup above.
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
