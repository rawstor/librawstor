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
// object.hpp's _writes_in_flight/_flush_waiters.
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
