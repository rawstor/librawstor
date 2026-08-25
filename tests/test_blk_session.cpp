#include "blk_session.hpp"
#include "connection.hpp"
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
#include <system_error>
#include <vector>

#include <cerrno>

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

// Pumps `q` until every Task in `tasks` has finished. A Task<T> must not be
// destroyed while still suspended (see rawstd/coro.hpp's own doc comment),
// so every caller that fires off more than one concurrently must drain
// them all like this before letting the vector go out of scope.
template <typename T>
void run_all(rawio::Queue& q, std::vector<rawstd::Task<T>>& tasks) {
    bool all_done = false;
    while (!all_done) {
        all_done = true;
        for (const auto& t : tasks) {
            if (!t.done()) {
                all_done = false;
                break;
            }
        }
        if (!all_done) {
            q.wait_timeout(rawstor_opts_tcp_user_timeout());
        }
    }
}

// Overrides rawstor_opts_write_throttle_limit()/write_backlog_capacity()
// for the lifetime of one test -- the real defaults are far too large to
// exercise the caps without pushing an impractical amount of data through
// them. Restores the library's normal opts (env vars/compiled-in
// defaults) on scope exit, same as tests/main.cpp's own initial
// rawstor_initialize(nullptr) set up.
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

// Stands up a real file:// object and a spare Connection/Session against
// it (independent of the Object's own internal one, same as
// Target::open()'s own _open_one() sets one up) so the test can drive
// blk::Session::pwrite() -- and inspect its throttle state -- directly.
rawstor::blk::Session* open_blk_session(
    rawio::Queue& queue, const rawstd::URI& location,
    std::unique_ptr<rawstor::Object>& object,
    std::unique_ptr<rawstor::Connection>& cn
) {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    rawstor::Target target({rawstd::URI(location, uuid_string)});

    RawstorObjectSpec spec{.size = 1u << 20};
    run(queue, target.create(queue, spec));

    object = run(queue, target.open(queue));

    cn = run(queue, rawstor::Connection::create(queue, location, 1));
    run(queue, cn->open(object.get()));

    return static_cast<rawstor::blk::Session*>(cn->get_next_session().get());
}

} // namespace

// A backing store slower than the incoming write rate must not let
// rawstor_object_pwrite() dispatch an unbounded number of concurrent
// writes to it -- see blk_session.hpp's _throttle_acquire(). Firing every
// write back to back, with nothing pumping the queue in between, means
// none of them can have completed yet by the time writes_in_flight() is
// read below: whatever it reports is exactly how many of these writes
// _throttle_acquire() let straight through before making the rest wait.
TEST(BlkSessionTest, write_throttle_limit) {
    constexpr unsigned int limit = 4;
    constexpr unsigned int writes = 20;
    ThrottleOptsOverride opts_override(limit, 1u << 20);

    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Object> object;
    std::unique_ptr<rawstor::Connection> cn;
    rawstor::blk::Session* session =
        open_blk_session(*queue, location, object, cn);

    std::string payload = "throttle-me";
    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(writes);
    for (unsigned int i = 0; i < writes; ++i) {
        tasks.push_back(session->pwrite(
            payload.data(), payload.size(), i * payload.size(), false
        ));
    }

    // The invariant write-throttle-limit exists for: no matter how many
    // writes came in at once, no more than the configured cap were ever
    // dispatched to storage concurrently.
    EXPECT_EQ(session->writes_in_flight(), limit);

    run_all(*queue, tasks);

    for (auto& t : tasks) {
        EXPECT_EQ(t.get(), payload.size());
    }
}

// Even with write-throttle-limit in place, a backing store slower than the
// incoming write rate must not let an unbounded number of already-received
// writes queue up waiting for a dispatch slot -- see blk_session.hpp's
// _throttle_acquire(). A throttle-limit of 1 puts every write from the
// second one onward on the backlog-check path immediately; same as
// write_throttle_limit above, firing every write with nothing pumping the
// queue in between means pending_writes_bytes() below reflects exactly
// what _throttle_acquire() queued before starting to reject outright.
TEST(BlkSessionTest, write_backlog_capacity) {
    constexpr unsigned int throttle_limit = 1;
    const std::string payload(16, 'x');
    constexpr size_t backlog_capacity_multiple = 3;
    const size_t backlog_capacity = payload.size() * backlog_capacity_multiple;
    constexpr unsigned int writes = 50;
    ThrottleOptsOverride opts_override(
        throttle_limit, static_cast<unsigned int>(backlog_capacity)
    );

    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(256);

    std::unique_ptr<rawstor::Object> object;
    std::unique_ptr<rawstor::Connection> cn;
    rawstor::blk::Session* session =
        open_blk_session(*queue, location, object, cn);

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(writes);
    for (unsigned int i = 0; i < writes; ++i) {
        tasks.push_back(session->pwrite(
            payload.data(), payload.size(), i * payload.size(), false
        ));
    }

    // The invariant write-backlog-capacity exists for: the backlog never
    // grows past the configured cap.
    EXPECT_EQ(session->pending_writes_bytes(), backlog_capacity);

    run_all(*queue, tasks);

    unsigned int accepted = 0;
    unsigned int rejected = 0;
    for (auto& t : tasks) {
        try {
            EXPECT_EQ(t.get(), payload.size());
            ++accepted;
        } catch (const std::system_error& e) {
            EXPECT_EQ(e.code().value(), EBUSY);
            ++rejected;
        }
    }

    // With 50 writes fired at a backlog that only fits 3 at once, some
    // must have been accepted and some must have been rejected with
    // EBUSY -- otherwise the cap wasn't actually exercised.
    EXPECT_GT(accepted, 0u);
    EXPECT_GT(rejected, 0u);
    EXPECT_EQ(accepted + rejected, writes);
}
