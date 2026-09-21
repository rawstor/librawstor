#include "chunk.hpp"
#include "opts.h"
#include "server.hpp"
#include "session.hpp"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

// Duplicate of chunk.cpp's own `run()` -- see that one's doc comment for
// why it isn't shared.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

// Duplicate of test_blk_backend.cpp's own ThrottleOptsOverride -- see that
// one's doc comment for why it isn't shared.
class ThrottleOptsOverride final {
public:
    ThrottleOptsOverride(
        unsigned int write_throttle_limit, unsigned int write_backlog_capacity
    ) {
        RawstorOpts opts{};
        opts.write_throttle_limit = write_throttle_limit;
        opts.write_backlog_capacity = write_backlog_capacity;
        rawstor_opts_initialize(&opts);
    }
    ThrottleOptsOverride(const ThrottleOptsOverride&) = delete;
    ThrottleOptsOverride(ThrottleOptsOverride&&) = delete;

    ~ThrottleOptsOverride() { rawstor_opts_initialize(nullptr); }

    ThrottleOptsOverride& operator=(const ThrottleOptsOverride&) = delete;
    ThrottleOptsOverride& operator=(ThrottleOptsOverride&&) = delete;
};

// Waits for a value set on rawstor::tests::Server's own background thread
// (server.hpp) -- unlike write_task.done()/flush_task.done(), nothing
// about that thread's progress is itself a completion on `queue`. But
// `queue` still needs pumping here regardless: Queue::wait_timeout()'s own
// io_uring_submit_and_wait_timeout() call is what actually flushes a
// previously-queued op's SQE to the kernel (see uring_queue.cpp) -- without
// it, a write issued right before this call never leaves the socket for
// the Server thread to read in the first place. A short timeout, its
// (expected -- there's nothing of the client's own left to complete while
// only the Server thread is still working) ETIME swallowed, keeps this
// from blocking for `value`'s full budget on each spin.
void wait_for_nonzero(rawio::Queue& queue, const std::atomic<uint16_t>& value) {
    for (int i = 0; i < 5000 && value.load() == 0; ++i) {
        try {
            queue.wait_timeout(1);
        } catch (const std::exception&) {
        }
    }
    ASSERT_NE(value.load(), 0);
}

// Stands up a real file:// object for the test to drive Chunk::pwrite()/
// flush() directly -- and inspect writes_in_flight()/flush()'s wait for it.
std::unique_ptr<rawstor::Chunk>
open_object(rawio::Queue& queue, const rawstd::URI& location) {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    rawstor::Target target({rawstd::URI(location, uuid_string)});

    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
    };
    run(queue, target.create(queue, spec));

    return run(queue, rawstor::Chunk::create(queue, id, 0, target.uris()));
}

} // namespace

// flush() must not report success while a write issued before it is still
// outstanding -- otherwise a caller relying on flush() for durability could
// observe success before that write's data is actually durable. See
// chunk.hpp's _writes_issued/_writes_completed/_flush_waiters.
TEST(ChunkTest, flush_waits_for_writes_issued_before_it) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Chunk> object = open_object(*queue, location);

    std::string payload = "durable-me";
    rawstd::Task<size_t> write_task =
        object->pwrite(payload.data(), payload.size(), 0, false);

    // Task<T> starts eagerly -- pwrite() has already run up to its first
    // suspension point (a real io_uring op), so writes_in_flight() is
    // already 1 even though nothing has pumped the queue yet.
    ASSERT_EQ(object->writes_in_flight(), 1u);
    ASSERT_FALSE(write_task.done());

    rawstd::Task<void> flush_task = object->flush();

    while (!write_task.done()) {
        // The write issued before flush() hasn't completed yet -- flush()
        // must still be waiting for it, not racing ahead to report success.
        ASSERT_FALSE(flush_task.done());
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }

    while (!flush_task.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }

    EXPECT_EQ(write_task.get(), payload.size());
    flush_task.get();
}

// flush() must not wait for writes issued *after* it either -- otherwise,
// under a continuous write stream (a new write always dispatched before an
// older one completes), the "everything outstanding has drained" condition
// could never actually occur and flush() would starve forever. Issuing a
// large batch of writes strictly after flush() and confirming most of them
// are still outstanding once flush() resolves demonstrates flush() is
// waiting for its own fixed snapshot (see chunk.hpp), not for the backlog
// to empty out.
//
// A throttle limit of 1 is what keeps this deterministic rather than a
// timing race: with it, write #2 onward cannot even be *dispatched* until
// its predecessor completes (see blk_backend.hpp's _throttle_acquire()),
// so draining all of them takes extra_writes strictly sequential round
// trips -- while flush() only ever needs write_task's single completion
// plus its own durability op, a handful at most. Without the throttle, a
// backend fast enough (observed on CI, against a tmpfs-backed file) can
// race every extra write to completion before flush() is even checked
// again, making the assertion below flaky.
TEST(ChunkTest, flush_does_not_wait_for_writes_issued_after_it) {
    constexpr unsigned int throttle_limit = 1;
    constexpr unsigned int extra_writes = 500;
    std::string payload = "durable-me";
    ThrottleOptsOverride opts_override(
        throttle_limit,
        static_cast<unsigned int>(payload.size() * (extra_writes + 1))
    );

    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Chunk> object = open_object(*queue, location);

    rawstd::Task<size_t> write_task =
        object->pwrite(payload.data(), payload.size(), 0, false);

    rawstd::Task<void> flush_task = object->flush();

    std::vector<rawstd::Task<size_t>> extra;
    extra.reserve(extra_writes);
    for (unsigned int i = 0; i < extra_writes; ++i) {
        extra.push_back(object->pwrite(
            payload.data(), payload.size(), (i + 1) * payload.size(), false
        ));
    }

    while (!flush_task.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    flush_task.get();
    EXPECT_EQ(write_task.get(), payload.size());

    unsigned int extra_done = 0;
    for (const auto& t : extra) {
        if (t.done()) {
            ++extra_done;
        }
    }
    // If flush() had (incorrectly) waited for the backlog to empty out
    // instead of just the write issued before it, every one of these would
    // already be done by the time flush() resolved.
    EXPECT_LT(extra_done, extra_writes);

    for (auto& t : extra) {
        while (!t.done()) {
            queue->wait_timeout(rawstor_opts_tcp_user_timeout());
        }
        EXPECT_EQ(t.get(), payload.size());
    }
}

// Multiple flush() calls in flight at once (e.g. two independent callers,
// or a caller that didn't wait for its own previous flush() before issuing
// another) must each resolve correctly, independent of one another --
// _flush_waiters holds one (target, handle) entry per call, so this isn't
// a single shared piece of state that a second flush() could stomp on.
TEST(ChunkTest, concurrent_flush_calls_all_resolve) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Chunk> object = open_object(*queue, location);

    std::string payload = "durable-me";
    rawstd::Task<size_t> write1 =
        object->pwrite(payload.data(), payload.size(), 0, false);

    // Two flush() calls sharing the same target -- no write issued between
    // them -- both must resolve once write1 completes.
    rawstd::Task<void> flush1 = object->flush();
    rawstd::Task<void> flush2 = object->flush();

    // A write issued after both flush() calls -- neither should wait for
    // it (see flush_does_not_wait_for_writes_issued_after_it above).
    rawstd::Task<size_t> write2 =
        object->pwrite(payload.data(), payload.size(), payload.size(), false);

    while (!flush1.done() || !flush2.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    flush1.get();
    flush2.get();
    EXPECT_EQ(write1.get(), payload.size());

    while (!write2.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    EXPECT_EQ(write2.get(), payload.size());
}

// close() must not proceed to close a connection while a write issued
// before it is still outstanding -- otherwise that write's own I/O could
// race the connection/fd being torn down under it. See Chunk::close()'s
// own doc comment (it calls flush(), which already has this wait).
TEST(ChunkTest, close_waits_for_writes_issued_before_it) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Chunk> object = open_object(*queue, location);

    std::string payload = "durable-me";
    rawstd::Task<size_t> write_task =
        object->pwrite(payload.data(), payload.size(), 0, false);
    ASSERT_FALSE(write_task.done());

    rawstd::Task<void> close_task = object->close();

    while (!write_task.done()) {
        // The write hasn't completed yet -- close() must still be
        // waiting for it, not racing ahead to tear down its connection.
        ASSERT_FALSE(close_task.done());
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }

    while (!close_task.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }

    EXPECT_EQ(write_task.get(), payload.size());
    close_task.get();
}

// Regression for the bug _write_finished()'s own doc comment describes:
// flush() must keep waiting for the specific write it was promised
// (write A, issued before it), not resolve just because *some* write
// completed. A plain completion count can't tell those apart; only a
// real network connection can produce genuine out-of-order completion
// deterministically enough to test it (real file:// I/O timing can't be
// controlled this precisely) -- so this drives an ost:// object over a
// scripted rawstor::tests::Server connection and answers write B's
// (issued after flush()) wire request before write A's, exactly as a
// real OST server answering out of cid order could.
TEST(ChunkTest, flush_does_not_resolve_on_write_completing_out_of_order) {
    rawstor::tests::Server server(8753, 256);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);
    rawstd::URI location("ost://127.0.0.1:8753");
    rawstor::Target target({rawstd::URI(location, uuid_string)});

    RawstorOSTFrameMetaPayload clean_meta = {
        .size = 1ull << 20,
        .reserved1 = 0,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .width = 1,
        .reserved2 = 0,
        .reserved3 = 0,
    };

    // Left open for the whole test -- see server.hpp's Session::~Session()
    // doc comment; closing it early would drop the connection Chunk is
    // about to hold onto for its writes/flush below.
    rawstor::tests::Session s(server);
    s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 1);
    s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
    s.cmd_meta(RAWSTOR_MAGIC, 2, 0, clean_meta);

    std::unique_ptr<rawstor::Chunk> object =
        run(*queue, rawstor::Chunk::create(*queue, id, 0, target.uris()));

    std::string payload_a = "write-a-";
    std::string payload_b = "write-b-";

    rawstd::Task<size_t> write_a =
        object->pwrite(payload_a.data(), payload_a.size(), 0, false);
    ASSERT_FALSE(write_a.done());

    rawstd::Task<void> flush_task = object->flush();

    rawstd::Task<size_t> write_b = object->pwrite(
        payload_b.data(), payload_b.size(), payload_a.size(), false
    );
    ASSERT_FALSE(write_b.done());

    // Read each WRITE request's own cid straight off the wire instead of
    // predicting it -- it's whatever Backend::_cid_counter happens to be
    // at that point (see ost_backend.hpp), not something this test needs
    // to (or should) hardcode. atomic because these are written on the
    // Server's own background thread (server.hpp) and polled from this
    // one below.
    std::atomic<uint16_t> cid_a{0};
    std::atomic<uint16_t> cid_b{0};
    server.read(
        "WRITE A head <<<", sizeof(RawstorOSTFrameHead),
        [&cid_a](const void* buf) {
            cid_a = static_cast<const RawstorOSTFrameHead*>(buf)->cid;
        }
    );
    server.read(
        "WRITE A rest <<<",
        sizeof(RawstorOSTFrameIO) - sizeof(RawstorOSTFrameHead) +
            payload_a.size(),
        [](const void*) {}
    );
    server.read(
        "WRITE B head <<<", sizeof(RawstorOSTFrameHead),
        [&cid_b](const void* buf) {
            cid_b = static_cast<const RawstorOSTFrameHead*>(buf)->cid;
        }
    );
    server.read(
        "WRITE B rest <<<",
        sizeof(RawstorOSTFrameIO) - sizeof(RawstorOSTFrameHead) +
            payload_b.size(),
        [](const void*) {}
    );

    wait_for_nonzero(*queue, cid_b);

    // Answer write B -- the one flush() was never promised to wait for --
    // before write A, forcing the exact out-of-order completion a real
    // cid-matched OST response could produce on the wire.
    RawstorOSTFrameResponse write_b_response = {
        .head{.magic = RAWSTOR_MAGIC, .cmd = RAWSTOR_CMD_WRITE, .cid = cid_b},
        .body = {.hash = 0, .res = static_cast<int32_t>(payload_b.size())},
    };
    server.write(
        "RAWSTOR_CMD_WRITE (B) >>>", &write_b_response, sizeof(write_b_response)
    );

    while (!write_b.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    EXPECT_EQ(write_b.get(), payload_b.size());

    // B completing early must not be mistaken for A's completion: with
    // the old plain-count tracking, this is exactly where flush() would
    // have (incorrectly) already resolved.
    EXPECT_FALSE(flush_task.done());

    wait_for_nonzero(*queue, cid_a);
    RawstorOSTFrameResponse write_a_response = {
        .head{.magic = RAWSTOR_MAGIC, .cmd = RAWSTOR_CMD_WRITE, .cid = cid_a},
        .body = {.hash = 0, .res = static_cast<int32_t>(payload_a.size())},
    };
    server.write(
        "RAWSTOR_CMD_WRITE (A) >>>", &write_a_response, sizeof(write_a_response)
    );

    while (!write_a.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    EXPECT_EQ(write_a.get(), payload_a.size());

    // Only now should flush() have moved on to its own wire-level FLUSH
    // (see Chunk::flush()'s own comment: it waits for the barrier first).
    std::atomic<uint16_t> cid_flush{0};
    server.read(
        "FLUSH head <<<", sizeof(RawstorOSTFrameHead),
        [&cid_flush](const void* buf) {
            cid_flush = static_cast<const RawstorOSTFrameHead*>(buf)->cid;
        }
    );
    server.read(
        "FLUSH rest <<<",
        sizeof(RawstorOSTFrameBasic) - sizeof(RawstorOSTFrameHead),
        [](const void*) {}
    );

    wait_for_nonzero(*queue, cid_flush);

    RawstorOSTFrameResponse flush_response = {
        .head{
            .magic = RAWSTOR_MAGIC, .cmd = RAWSTOR_CMD_FLUSH, .cid = cid_flush
        },
        .body = {.hash = 0, .res = 0},
    };
    server.write(
        "RAWSTOR_CMD_FLUSH >>>", &flush_response, sizeof(flush_response)
    );

    while (!flush_task.done()) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    flush_task.get();
}
