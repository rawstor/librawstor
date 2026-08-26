#include "object.hpp"
#include "opts.h"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

namespace {

// Duplicate of object.cpp's own `run()` -- see that one's doc comment for
// why it isn't shared.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

// Duplicate of test_blk_session.cpp's own ThrottleOptsOverride -- see that
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

// Stands up a real file:// object for the test to drive Object::pwrite()/
// flush() directly -- and inspect writes_in_flight()/flush()'s wait for it.
std::unique_ptr<rawstor::Object>
open_object(rawio::Queue& queue, const rawstd::URI& location) {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    rawstor::Target target({rawstd::URI(location, uuid_string)});

    RawstorObjectSpec spec{.size = 1u << 20};
    run(queue, target.create(queue, spec));

    return run(queue, target.open(queue));
}

} // namespace

// flush() must not report success while a write issued before it is still
// outstanding -- otherwise a caller relying on flush() for durability could
// observe success before that write's data is actually durable. See
// object.hpp's _writes_issued/_writes_completed/_flush_waiters.
TEST(ObjectTest, flush_waits_for_writes_issued_before_it) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Object> object = open_object(*queue, location);

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
// waiting for its own fixed snapshot (see object.hpp), not for the backlog
// to empty out.
//
// A throttle limit of 1 is what keeps this deterministic rather than a
// timing race: with it, write #2 onward cannot even be *dispatched* until
// its predecessor completes (see blk_session.hpp's _throttle_acquire()),
// so draining all of them takes extra_writes strictly sequential round
// trips -- while flush() only ever needs write_task's single completion
// plus its own durability op, a handful at most. Without the throttle, a
// backend fast enough (observed on CI, against a tmpfs-backed file) can
// race every extra write to completion before flush() is even checked
// again, making the assertion below flaky.
TEST(ObjectTest, flush_does_not_wait_for_writes_issued_after_it) {
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

    std::unique_ptr<rawstor::Object> object = open_object(*queue, location);

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
TEST(ObjectTest, concurrent_flush_calls_all_resolve) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Object> object = open_object(*queue, location);

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
// race the connection/fd being torn down under it. See Object::close()'s
// own doc comment (it calls flush(), which already has this wait).
TEST(ObjectTest, close_waits_for_writes_issued_before_it) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Object> object = open_object(*queue, location);

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
