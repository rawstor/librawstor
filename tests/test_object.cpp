// mds::Backend::create_snapshot()/remove() (docs/mds.md, "Snapshots
// (stage 2)"), exercised against a real rawstor::mdsserver::Server +
// rawstor::ostserver::Server pair (object_env.hpp) -- the actual wire
// path a `mds://` target goes through, not a hand-scripted mock of it.
// The OST's only backend is file://, which has no native CoW, so every
// case here is a negative-path/error-propagation test: the positive CoW
// path needs a live zfs pool and isn't reachable from a portable test
// (see object_env.hpp's own doc comment).
#include "backend.hpp"
#include "mds_client.hpp"
#include "object_env.hpp"
#include "rawio_sync.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/list.h>
#include <rawstor/location.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>

#include <cerrno>

namespace {

// Drives one coroutine to completion on `q` (same helper as
// test_multichunk.cpp's own).
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait();
    }
    return t.get();
}

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

ssize_t location_create(
    rawio::Queue& queue, const std::string& location,
    const RawstorObjectSpec& spec, char* target, size_t size
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_create(
            &queue, location.c_str(), nullptr, &spec, target, size, cb, data
        );
    });
}

ssize_t target_remove(rawio::Queue& queue, const std::string& target) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_remove(&queue, target.c_str(), cb, data);
    });
}

// Appends `snapshot_id` as a bound-snapshot path segment to `target`
// (rawstor_target_snapshot_id()'s own convention) -- the caller binds
// the snapshot into the target string itself; rawstor_target_create()/
// _remove() take no separate snapshot_id parameter.
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

ssize_t target_set_member_sync_state(
    rawio::Queue& queue, const std::string& target, uint64_t offset,
    size_t member_index, const RawstorObjectSyncState& sync_state
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_set_member_sync_state(
            &queue, target.c_str(), offset, member_index, &sync_state, cb, data
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
    spec.chunk_size = spec.size;
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

// A snapshot attempt that never reaches OBJ_COMMIT_SNAPSHOT (every chunk
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

// remove_snapshot() on an id nothing ever committed fails cleanly with
// -ENOENT (the MDS's own rejection), not a hang or a crash -- this is
// the same case a crash mid-fan-out (before OBJ_COMMIT_SNAPSHOT) leaves
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

// LIST against the MDS: every object it knows, each as the same id-only
// mds:// target create() used, a page at a time.
TEST(ObjectListTest, lists_mds_objects) {
    rawstor::tests::ObjectEnv env(8804, 8805);
    std::vector<std::string> targets = {
        object_target(env, "018f4e2a-3000-7000-8000-000000000050"),
        object_target(env, "018f4e2a-3000-7000-8000-000000000051"),
    };

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    for (const std::string& target : targets) {
        ASSERT_EQ(target_create(*queue, target, spec), 0);
    }

    std::string location = env.location();
    std::vector<std::string> listed;
    RawstorPaginationToken token = {};
    size_t pages = 0;
    do {
        RawstorStringList* page = nullptr;
        ssize_t res =
            rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
                return rawstor_location_list(
                    queue.get(), location.c_str(), 1, &page, &token, cb, data
                );
            });
        ASSERT_EQ(res, 0);
        for (const char** it = rawstor_string_list_iter(page); it != nullptr;
             it = rawstor_string_list_next(it)) {
            listed.push_back(*it);
        }
        rawstor_string_list_delete(page);
        ++pages;
    } while (!rawstor_pagination_token_empty(&token) && pages < 10);

    EXPECT_EQ(listed, targets);
    EXPECT_GE(pages, 2u);

    for (const std::string& target : targets) {
        EXPECT_EQ(target_remove(*queue, target), 0);
    }
}

// An mds:// Backend left with no nested object -- closed, or its re-open
// failed -- reports every data-path call as a retryable ENOTCONN, the way
// a closed socket does, so Slot's retry reconnects instead of crashing.
TEST(ObjectCloseTest, mds_backend_io_after_close_is_enotconn) {
    rawstor::tests::ObjectEnv env(8806, 8807);
    const char* uuid = "018f4e2a-3000-7000-8000-000000000060";
    std::string target = object_target(env, uuid);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid_from_string(&id, uuid), 0);
    std::shared_ptr<rawstor::Backend> backend =
        run(*queue,
            rawstor::Backend::create(*queue, rawstd::URI(env.location())));
    run(*queue, backend->set_object(id, 0, 0));
    run(*queue, backend->close());

    auto expect_enotconn = [&](auto task) {
        try {
            run(*queue, std::move(task));
            ADD_FAILURE() << "no error";
        } catch (const std::system_error& e) {
            EXPECT_EQ(e.code().value(), ENOTCONN);
        }
    };
    char buf[4096] = {};
    expect_enotconn(backend->flush());
    expect_enotconn(backend->pread(buf, sizeof(buf), 0));
    expect_enotconn(backend->pwrite(buf, sizeof(buf), 0, false));

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// OBJ_LIST_SNAPSHOTS end to end: an object with no committed snapshot
// lists none, and an object the MDS doesn't know is ENOENT.
TEST(ObjectSnapshotTest, list_snapshots_over_mds) {
    rawstor::tests::ObjectEnv env(8802, 8803);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000040");
    std::string unknown =
        object_target(env, "018f4e2a-3000-7000-8000-000000000041");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    auto list = [&](const std::string& t) {
        RawstorStringList* snapshots = nullptr;
        ssize_t res =
            rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
                return rawstor_target_snapshots(
                    queue.get(), t.c_str(), &snapshots, cb, data
                );
            });
        rawstor_string_list_delete(snapshots);
        return res;
    };
    EXPECT_EQ(list(target), 0);
    EXPECT_EQ(list(unknown), -ENOENT);

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
        "test_object_snapshot_assign_enotsup",
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
        "test_object_snapshot_bound_id", "018f4e2a-3000-7000-8000-00000000000d"
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
        "test_object_snapshot_explicit_id",
        "018f4e2a-3000-7000-8000-00000000000f"
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
        "test_object_snapshot_conflict", "018f4e2a-3000-7000-8000-000000000011"
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

// rawstor_target_meta() resolves offset 0 to this object's own real
// (only) chunk and reports that chunk's own real member's real mirror
// state (mds::Backend::meta()'s own doc comment) -- a single-chunk,
// single-member object's own chunk 0 answers with exactly the values
// its own create() call established: `spec.size` the chunk's own
// physical size (the object's own logical size too, since there's only
// the one chunk), a freshly-created single member trusted CLEAN with no
// sync_id of its own yet (docs/mirroring.md, "legacy copy").
// rawstor_target_set_member_sync_state() below writes straight to that
// one real member's own Slot (Target::set_member_sync_state()'s own doc
// comment) instead of going through mds::Backend::set_sync_state()
// (which stays a whole-object-level no-op, mds_backend.cpp's own
// comment) -- so it persists for real even on an mds:: target.
TEST(ObjectMetaTest, meta_on_object_target_is_real) {
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

TEST(ObjectMetaTest, set_member_sync_state_on_object_target_is_real) {
    rawstor::tests::ObjectEnv env(8788, 8789);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-00000000000c");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstorObjectSyncState sync_state{};
    sync_state.epoch = 5;
    sync_state.sync_id = 0x1122334455667788ull;
    sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    EXPECT_EQ(
        target_set_member_sync_state(*queue, target, 0, 0, sync_state), 0
    );

    RawstorObjectMeta meta{};
    ASSERT_EQ(target_meta(*queue, target, 0, &meta, 1), 1);
    EXPECT_EQ(meta.sync_state.epoch, 5u);
    EXPECT_EQ(meta.sync_state.sync_id, 0x1122334455667788ull);
    EXPECT_EQ(meta.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// Growing a multi-chunk object reserves placement for the new chunks on
// the MDS and materializes exactly those on the OST -- spec() reflects
// the new size.
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
    spec.chunk_size = spec.size / 2;
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

// Growth only ever adds whole chunks: a new size that isn't a multiple of
// the object's own chunk_size is rejected before the MDS is asked.
TEST(ObjectResizeTest, not_chunk_multiple_is_einval) {
    rawstor::tests::ObjectEnv env(8796, 8797);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000020");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    EXPECT_EQ(
        object_resize(*queue, target, spec.size + spec.size / 2), -EINVAL
    );

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, spec.size);

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// An mds:// object is always chunked: there is no chunk_size to derive
// for it, so 0 is rejected.
TEST(ObjectCreateTest, mds_without_chunk_size_is_einval) {
    rawstor::tests::ObjectEnv env(8798, 8799);
    std::string target =
        object_target(env, "018f4e2a-3000-7000-8000-000000000021");

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    spec.chunk_size = 0;
    EXPECT_EQ(target_create(*queue, target, spec), -EINVAL);
}

// Every chunk is exactly chunk_size, so the object's own size must be a
// whole number of them -- checked for any target, not just mds://.
TEST(ObjectCreateTest, size_not_chunk_multiple_is_einval) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);
    std::string target = file_target(
        "test_object_create_not_multiple",
        "018f4e2a-3000-7000-8000-000000000022"
    );

    RawstorObjectSpec spec = one_chunk_spec();
    spec.chunk_size = spec.size / 4;
    spec.size += spec.chunk_size / 2;
    EXPECT_EQ(target_create(*queue, target, spec), -EINVAL);
}

// A resize whose reply got lost is retried with the same idempotency_key
// (docs/mds.md, "Idempotent mutations"): the MDS has already grown the map,
// so the retry must still materialize the new chunks it reserved --
// not see a map that already has them and create none. The "lost" first
// attempt is an OBJ_RESIZE sent straight through an mds::Client, whose
// reply is simply dropped.
TEST(ObjectResizeTest, retried_after_lost_reply_materializes_new_chunks) {
    rawstor::tests::ObjectEnv env(8800, 8801);
    const char* uuid = "018f4e2a-3000-7000-8000-000000000030";
    std::string target = object_target(env, uuid);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec = one_chunk_spec();
    spec.chunk_size = spec.size / 2;
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid_from_string(&id, uuid), 0);
    RawstdUUID idempotency_key;
    ASSERT_EQ(rawstd_uuid7_init(&idempotency_key), 0);
    uint64_t new_size = 2 * spec.size;

    {
        rawstor::mds::Client client(*queue, rawstd::URI(env.location()));
        run(*queue, client.connect());
        run(*queue, client.resize(idempotency_key, id, new_size));
    }

    std::shared_ptr<rawstor::Backend> backend =
        run(*queue,
            rawstor::Backend::create(*queue, rawstd::URI(env.location())));
    run(*queue, backend->resize(idempotency_key, id, 0, new_size));
    // Retried once more after every new copy already exists: each one's
    // create() now answers EEXIST, which a retry counts as already done.
    run(*queue, backend->resize(idempotency_key, id, 0, new_size));
    run(*queue, backend->close());

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target, &read_spec), 0);
    EXPECT_EQ(read_spec.size, new_size);

    // Every chunk the resize added has its copy on the OST.
    for (uint64_t offset = spec.size; offset < new_size;
         offset += spec.chunk_size) {
        RawstorObjectMeta meta{};
        ASSERT_EQ(target_meta(*queue, target, offset, &meta, 1), 1) << offset;
        EXPECT_EQ(meta.spec.size, spec.chunk_size) << offset;
    }

    EXPECT_EQ(target_remove(*queue, target), 0);
}

// resize() makes no sense against a plain (non-"mds://") target -- no
// MDS to reserve placement with. Unified dispatch (target.cpp) does not
// reject this client-side by scheme: it reaches the target's own
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

// mds::Backend::create() ignores its own chunk_offset parameter and does
// its own placement-driven chunking internally, off spec.size/chunk_size
// directly, given exactly one whole-object call -- rawstor_location_
// create() must not also split an mds:// location's own URI into several
// offset-stamped copies the way it does for a plain (file/lvm/zfs)
// location (src/location.cpp's build_create_uris()), or Target::create()'s
// own per-group fan-out would call it more than once, each time with only
// that one group's own reduced share of size. The target this returns
// names the whole object with a single, bare mds:// URI -- not a
// comma-joined, offset-stamped one -- and its own reported size is the
// real, undivided total.
TEST(ObjectCreateTest, location_create_with_chunk_size_creates_one_object) {
    rawstor::tests::ObjectEnv env(8790, 8791);

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    RawstorObjectSpec spec{};
    spec.size = 2ull << 20; /* 2 MiB */
    spec.width = 1;
    spec.chunk_size = 512ull << 10; /* 512 KiB -- 4 real chunks */

    char target[65536];
    ssize_t res =
        location_create(*queue, env.location(), spec, target, sizeof(target));
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, sizeof(target));

    std::string target_str(target, static_cast<size_t>(res));
    // A single, bare mds:// URI -- no comma (one URI, not several) and no
    // manufactured offset segment.
    EXPECT_EQ(target_str.find(','), std::string::npos);
    rawstd::URI location_uri(env.location());
    EXPECT_TRUE(target_str.rfind(location_uri.str(), 0) == 0);

    RawstorObjectSpec read_spec{};
    ASSERT_EQ(target_spec(*queue, target_str, &read_spec), 0);
    EXPECT_EQ(read_spec.size, spec.size);

    EXPECT_EQ(target_remove(*queue, target_str), 0);
}
