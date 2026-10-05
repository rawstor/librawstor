#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include "opts.h"
#include "rawio_sync.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/list.h>
#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <sys/uio.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

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

// rawstor_target_meta() now takes an array (one entry per URI of the
// chunk at `offset`) instead of a single out-parameter -- every call
// site here queries a single-URI, single-chunk target at offset 0, so
// this keeps their own signature (one RawstorObjectMeta* out-parameter)
// by unwrapping that one entry.
ssize_t target_meta(
    rawio::Queue& queue, const std::string& target, RawstorObjectMeta* meta
) {
    ssize_t res = rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_meta(
            &queue, target.c_str(), 0, meta, 1, cb, data
        );
    });
    if (res < 0) {
        return res;
    }
    return meta->sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE
               ? -ENOTCONN
               : 0;
}

// Every call site here targets a single-URI, single-chunk target at
// offset 0, so its one member is index 0.
ssize_t target_set_sync_state(
    rawio::Queue& queue, const std::string& target,
    const RawstorObjectSyncState& sync_state
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_set_member_sync_state(
            &queue, target.c_str(), 0, 0, &sync_state, cb, data
        );
    });
}

ssize_t target_open(
    rawio::Queue& queue, const std::string& target, int flags,
    RawstorObject** object
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_open(
            &queue, target.c_str(), flags, object, cb, data
        );
    });
}

ssize_t object_close(rawio::Queue& queue, RawstorObject* object) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_object_close(object, cb, data);
    });
}

// rawstor_object_pread()'s own callback shape (size_t result, int error)
// doesn't fit rawstor::tests::sync_run()'s (ssize_t result) convention --
// shared by every other rawstor_target_*()/rawstor_object_close() call
// above -- so this pumps `queue` itself instead, the same way
// tests/test_chunk.cpp's own ChunkTest cases do.
ssize_t object_pread(
    rawio::Queue& queue, RawstorObject* object, void* buf, size_t size,
    uint64_t offset
) {
    struct Result {
        size_t result = 0;
        int error = 0;
        bool done = false;
    };
    Result r;

    int (*cb)(size_t, int, void*) = [](size_t result, int error,
                                       void* data) -> int {
        Result* r = static_cast<Result*>(data);
        r->result = result;
        r->error = error;
        r->done = true;
        return 0;
    };

    int res = rawstor_object_pread(object, buf, size, offset, cb, &r);
    if (res < 0) {
        return res;
    }

    while (!r.done) {
        queue.wait_timeout(rawstor_opts_tcp_user_timeout());
    }

    return r.error != 0 ? -r.error : static_cast<ssize_t>(r.result);
}

ssize_t location_list(
    rawio::Queue& queue, const std::string& location, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_list(
            &queue, location.c_str(), limit, targets, token, cb, data
        );
    });
}

ssize_t location_create(
    rawio::Queue& queue, const std::string& location, const char* uuid,
    const RawstorObjectSpec& spec, char* target, size_t size
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_create(
            &queue, location.c_str(), uuid, &spec, target, size, cb, data
        );
    });
}

TEST(FileLifecycleTest, create_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = target_create(*queue, target, spec);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec read_spec;
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = location_list(*queue, location, 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            // Location::list() always stamps an explicit offset segment,
            // even "0" -- unlike target's own bare, offset-less form here.
            EXPECT_EQ(target + "/0", *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

// remove() is retried by its Slot after a transient failure (e.g. ENOBUFS
// from a saturated queue), possibly after the failed attempt already
// unlinked the chunk's data file but not its meta file: the retry must
// finish the removal rather than report ENOENT. Only a chunk with nothing
// left of it is missing.
TEST(FileLifecycleTest, remove_finishes_interrupted_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-00000000000c";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(*queue, target, spec), 0);

    std::filesystem::path chunk_dir = dir.path() / uuid / "0";
    ASSERT_TRUE(std::filesystem::remove(chunk_dir / "data"));
    ASSERT_TRUE(std::filesystem::exists(chunk_dir / "meta"));

    EXPECT_EQ(target_remove(*queue, target), 0);
    EXPECT_FALSE(std::filesystem::exists(dir.path() / uuid));

    EXPECT_EQ(target_remove(*queue, target), -ENOENT);
}

// A failed create() must only roll back what THIS call itself created --
// a second create() on an already-existing target fails with EEXIST, and
// must not remove() the target the first call created.
TEST(FileLifecycleTest, create_twice_preserves_existing) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = target_create(*queue, target, spec);
    EXPECT_EQ(res, 0);

    res = target_create(*queue, target, spec);
    EXPECT_EQ(res, -EEXIST);

    RawstorObjectSpec read_spec;
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

// remove() on an already-removed target must fail with ENOENT, same as on
// a target that was never created at all (see file::Backend::remove()'s
// own doc comment) -- matches pyrawstor/tests/test_target.py's own
// test_remove_not_found expectation (FileNotFoundError), which this
// mirrors at the C++ level for the "removed, then removed again" shape
// specifically.
TEST(FileLifecycleTest, remove_already_removed_target_fails_with_enoent) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-000000000005";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = target_create(*queue, target, spec);
    ASSERT_EQ(res, 0);

    res = target_remove(*queue, target);
    ASSERT_EQ(res, 0);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, -ENOENT);
}

// A target naming a bound version can only be opened
// RAWSTOR_READONLY -- refused before any I/O otherwise.
TEST(FileLifecycleTest, open_version_without_readonly_is_einval) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-000000000008";
    std::string version_id = "00000000-0000-7000-8000-000000000009";
    std::string target =
        rawstd::URI(rawstd::URI(location_uri, uuid), version_id).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObject* object = nullptr;
    EXPECT_EQ(target_open(*queue, target, 0, &object), -EINVAL);
}

// With RAWSTOR_READONLY the open goes ahead and reaches the backend, which
// (file:// has no native CoW) answers ENOTSUP -- Chunk::create() then
// reports the lone member as unavailable, i.e. ENOTCONN.
TEST(FileLifecycleTest, open_version_readonly_reaches_backend) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-00000000000a";
    std::string version_id = "00000000-0000-7000-8000-00000000000b";
    std::string live = rawstd::URI(location_uri, uuid).str();
    std::string target = rawstd::URI(rawstd::URI(live), version_id).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.width = 1;
    ASSERT_EQ(target_create(*queue, live, spec), 0);

    RawstorObject* object = nullptr;
    EXPECT_EQ(
        target_open(*queue, target, RAWSTOR_READONLY, &object), -ENOTCONN
    );

    EXPECT_EQ(target_remove(*queue, live), 0);
}

// A freshly created object must read back as all zeros, even though
// nothing has ever been written to it -- file::Backend relies on a sparse
// regular file's own guarantee that an unwritten byte range always reads
// as zero, regardless of whether fallocate() actually ran (see create()'s
// own doc comment on why it preallocates at all -- performance, not
// zero-fill correctness). Poisons the buffer with a non-zero byte first so
// a bug that left it untouched can't accidentally read back as "already
// zero".
TEST(FileLifecycleTest, create_is_zero_filled) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-000000000006";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    constexpr size_t size = 1u << 20;
    RawstorObjectSpec spec{
        .size = size,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = target_create(*queue, target, spec);
    ASSERT_EQ(res, 0);

    RawstorObject* object = nullptr;
    res = target_open(*queue, target, 0, &object);
    ASSERT_EQ(res, 0);

    std::vector<unsigned char> buf(size, 0xff);
    ssize_t rres = object_pread(*queue, object, buf.data(), buf.size(), 0);
    EXPECT_EQ(rres, static_cast<ssize_t>(size));
    EXPECT_TRUE(std::all_of(buf.begin(), buf.end(), [](unsigned char c) {
        return c == 0;
    }));

    res = object_close(*queue, object);
    EXPECT_EQ(res, 0);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_default_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = location_create(
        *queue, location, nullptr, spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);

    RawstorObjectSpec read_spec = {};
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = location_list(*queue, location, 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            // Location::create()/list() both always stamp an explicit
            // offset segment, even "0" -- the two agree without any
            // adjustment here.
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

// rawstor_location_create() splits size into ceil(size / chunk_size)
// chunks itself when chunk_size is set -- the same (offset, mirror) shape
// a hand-built multi-offset -t/--target TARGET already names, without
// needing mds:// or any other placement orchestration.
TEST(FileLifecycleTest, create_at_chunk_size_splits_into_multiple_chunks) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000003";
    std::string target(65536, '\0');

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 2ull << 20,
        .width = 1,
        .chunk_size = 1ull << 20,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = location_create(
        *queue, location, uuid.c_str(), spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);

    // A genuine multi-chunk target names every one of its own chunks'
    // offsets explicitly, even "0" -- 1ull << 20 is "100000" in hex.
    rawstd::URI id_uri(location_uri, uuid);
    EXPECT_EQ(
        target, rawstd::URI::uris(
                    {rawstd::URI(id_uri, "0"), rawstd::URI(id_uri, "100000")}
                )
    );

    RawstorObjectSpec read_spec = {};
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(2ull << 20));

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000002";
    std::string target(65536, '\0');

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = location_create(
        *queue, location, uuid.c_str(), spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);
    // Location::create() always stamps an explicit offset segment, even
    // "0" -- matching Location::list()'s own returned target strings, so
    // a caller comparing the two (pyrawstor's own Target.__eq__) sees
    // them agree.
    EXPECT_EQ(target, rawstd::URI(rawstd::URI(location_uri, uuid), "0").str());

    RawstorObjectSpec read_spec = {};
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = location_list(*queue, location, 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            // Location::create()/list() both always stamp an explicit
            // offset segment, even "0" -- the two agree without any
            // adjustment here.
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, meta_set_state) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ssize_t res = target_create(*queue, target, spec);
    EXPECT_EQ(res, 0);

    RawstorObjectMeta meta{};
    res = target_meta(*queue, target, &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.spec.size, 1ull << 20);
    EXPECT_EQ(meta.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(meta.sync_state.epoch, 0u);
    EXPECT_EQ(meta.sync_state.sync_id, 0u);
    for (size_t i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; ++i) {
        EXPECT_EQ(meta.sync_state.sync_id_history[i], 0u);
    }

    RawstorObjectSyncState next{};
    next.epoch = 3;
    next.sync_id = 0x1122334455667788ull;
    next.sync_id_history[0] = 0xaabbccddeeff0011ull;
    next.state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
    res = target_set_sync_state(*queue, target, next);
    EXPECT_EQ(res, 0);

    res = target_meta(*queue, target, &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.spec.size, 1ull << 20);
    EXPECT_EQ(meta.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.sync_state.epoch, 3u);
    EXPECT_EQ(meta.sync_state.sync_id, 0x1122334455667788ull);
    EXPECT_EQ(meta.sync_state.sync_id_history[0], 0xaabbccddeeff0011ull);
    EXPECT_EQ(meta.sync_state.sync_id_history[1], 0u);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(OstLifecycleTest, create_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string uuid = "00000000-0000-7000-8000-000000000003";
    std::string target = rawstd::URI(location_uri, uuid).str();

    RawstorFrameMetaPayload meta_body = {
        .size = 1ull << 20,
        .epoch = 7,
        .sync_id = 0x1122334455667788ull,
        .sync_id_history = {0xaabbccddeeff0011ull, 0, 0, 0},
        .state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY,
        .chunk_shift = 20,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
    };

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_state(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    {
        RawstorObjectSpec spec{
            .size = 1ull << 20,
            .width = 1,
            .chunk_size = 0,
            .stripe_width = 0,
            .failure_domain = 0,
        };

        ssize_t res = target_create(*queue, target, spec);
        EXPECT_EQ(res, 0);
    }

    {
        RawstorObjectSpec read_spec;
        ssize_t res = target_spec(*queue, target, &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        RawstorObjectMeta meta{};
        ssize_t res = target_meta(*queue, target, &meta);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(meta.spec.size, 1ull << 20);
        EXPECT_EQ(meta.spec.chunk_size, 1ull << 20);
        EXPECT_EQ(meta.sync_state.epoch, 7u);
        EXPECT_EQ(meta.sync_state.sync_id, 0x1122334455667788ull);
        EXPECT_EQ(meta.sync_state.sync_id_history[0], 0xaabbccddeeff0011ull);
        EXPECT_EQ(meta.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    }

    {
        RawstorObjectSyncState sync_state{};
        sync_state.epoch = 8;
        sync_state.sync_id = 0x99ull;
        sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
        ssize_t res = target_set_sync_state(*queue, target, sync_state);
        EXPECT_EQ(res, 0);
    }

    {
        ssize_t res = target_remove(*queue, target);
        EXPECT_EQ(res, 0);
    }
}

// A bound version's META asks the far end about that version: the
// version_id rides the request's own RawstorFrameBasicPayload.
TEST(OstLifecycleTest, meta_of_bound_version_carries_version_id) {
    rawstor::tests::Server server(8755, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8755");
    std::string uuid = "00000000-0000-7000-8000-000000000004";
    std::string version_str = "00000000-0000-7000-8000-000000000005";
    std::string target =
        rawstd::URI(rawstd::URI(location_uri, uuid), version_str).str();

    RawstorFrameMetaPayload meta_body = {
        .size = 1ull << 20,
        .epoch = 7,
        .sync_id = 0x11ull,
        .sync_id_history = {0, 0, 0, 0},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
    };

    auto requested = std::make_shared<RawstdUUID>();
    {
        rawstor::tests::Session s(server);
        server.read(
            "RAWSTOR_CMD_META <<<", sizeof(RawstorFrameBasic),
            [requested](const void* buf) {
                const RawstorFrameBasic* frame =
                    static_cast<const RawstorFrameBasic*>(buf);
                memcpy(
                    requested->bytes, frame->payload.version_id,
                    sizeof(requested->bytes)
                );
            }
        );
        s.cmd_meta_response(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectMeta meta{};
    ssize_t res = target_meta(*queue, target, &meta);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(meta.spec.size, 1ull << 20);

    RawstdUUID expected;
    ASSERT_EQ(rawstd_uuid_from_string(&expected, version_str.c_str()), 0);
    EXPECT_EQ(rawstd_uuid_cmp(requested.get(), &expected), 0);
}

// LIST_VERSIONS asks the far end about the object's own chunk, and every
// returned id becomes that version's own target string.
TEST(OstLifecycleTest, versions_over_wire) {
    rawstor::tests::Server server(8756, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8756");
    std::string uuid = "00000000-0000-7000-8000-000000000006";
    std::string target = rawstd::URI(location_uri, uuid).str();
    std::string versions[2] = {
        "00000000-0000-7000-8000-000000000007",
        "00000000-0000-7000-8000-000000000008",
    };

    RawstorFrameVersionEntry entries[2];
    for (size_t i = 0; i < 2; ++i) {
        RawstdUUID version_id;
        ASSERT_EQ(rawstd_uuid_from_string(&version_id, versions[i].c_str()), 0);
        memcpy(
            entries[i].version_id, version_id.bytes,
            sizeof(entries[i].version_id)
        );
    }

    auto requested = std::make_shared<RawstdUUID>();
    {
        rawstor::tests::Session s(server);
        server.read(
            "RAWSTOR_CMD_LIST_VERSIONS <<<", sizeof(RawstorFrameBasic),
            [requested](const void* buf) {
                const RawstorFrameBasic* frame =
                    static_cast<const RawstorFrameBasic*>(buf);
                memcpy(
                    requested->bytes, frame->payload.object_id,
                    sizeof(requested->bytes)
                );
            }
        );
        RawstorFrameResponse response = {
            .head{
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_LIST_VERSIONS,
                .cid = 0,
            },
            .body = {
                .hash = rawstd_hash_scalar(entries, sizeof(entries)),
                .res = static_cast<int32_t>(sizeof(entries)),
            },
        };
        iovec iov[2] = {
            {.iov_base = &response, .iov_len = sizeof(response)},
            {.iov_base = entries, .iov_len = sizeof(entries)},
        };
        server.writev("RAWSTOR_CMD_LIST_VERSIONS >>>", iov, 2);
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorStringList* list = nullptr;
    ssize_t res =
        rawstor::tests::sync_run(queue.get(), [&](auto cb, void* data) {
            return rawstor_target_versions(
                queue.get(), target.c_str(), &list, cb, data
            );
        });
    ASSERT_EQ(res, 2);

    std::vector<std::string> got;
    for (const char** it = rawstor_string_list_iter(list); it != nullptr;
         it = rawstor_string_list_next(it)) {
        got.push_back(*it);
    }
    rawstor_string_list_delete(list);
    ASSERT_EQ(got.size(), 2u);
    EXPECT_EQ(
        got[0], rawstd::URI(rawstd::URI(location_uri, uuid), versions[0]).str()
    );
    EXPECT_EQ(
        got[1], rawstd::URI(rawstd::URI(location_uri, uuid), versions[1]).str()
    );

    RawstdUUID expected;
    ASSERT_EQ(rawstd_uuid_from_string(&expected, uuid.c_str()), 0);
    EXPECT_EQ(rawstd_uuid_cmp(requested.get(), &expected), 0);
}

TEST(OstLifecycleTest, create_at_default_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    RawstorFrameMetaPayload meta_body = {
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
    };

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    {
        RawstorObjectSpec spec{
            .size = 1ull << 20,
            .width = 1,
            .chunk_size = 0,
            .stripe_width = 0,
            .failure_domain = 0,
        };

        ssize_t res = location_create(
            *queue, location, nullptr, spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
    }

    {
        RawstorObjectSpec read_spec = {};
        ssize_t res = target_spec(*queue, target, &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        ssize_t res = target_remove(*queue, target);
        EXPECT_EQ(res, 0);
    }
}

TEST(OstLifecycleTest, create_at_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000004";
    std::string target(65536, '\0');

    RawstorFrameMetaPayload meta_body = {
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
    };

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta_body);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    {
        RawstorObjectSpec spec{
            .size = 1ull << 20,
            .width = 1,
            .chunk_size = 0,
            .stripe_width = 0,
            .failure_domain = 0,
        };

        ssize_t res = location_create(
            *queue, location, uuid.c_str(), spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
        // Location::create() always stamps an explicit offset segment,
        // even "0" -- Location::list()'s own doc comment.
        EXPECT_EQ(
            target, rawstd::URI(rawstd::URI(location_uri, uuid), "0").str()
        );
    }

    {
        RawstorObjectSpec read_spec = {};
        ssize_t res = target_spec(*queue, target, &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        ssize_t res = target_remove(*queue, target);
        EXPECT_EQ(res, 0);
    }
}

} // unnamed namespace
