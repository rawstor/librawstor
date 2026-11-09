#include "object.hpp"
#include "object_env.hpp"
#include "opts.h"
#include "target.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <cerrno>

/*
 * The write barrier of a version (docs/mds.md, "The write barrier"), seen
 * from a real writer: while a member is frozen the writer waits, however
 * long, and its write completes once the member thaws.
 */

namespace {

template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

void run(rawio::Queue& q, rawstd::Task<void> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    t.get();
}

// Drives `q` until `t` is done or `msec` passes; tells which.
template <typename T>
bool run_for(rawio::Queue& q, rawstd::Task<T>& t, unsigned int msec) {
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(msec);
    while (!t.done() && std::chrono::steady_clock::now() < deadline) {
        try {
            q.wait_timeout(20);
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
    return t.done();
}

RawstdUUID new_id() {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    return id;
}

std::string id_string(const RawstdUUID& id) {
    RawstdUUIDString s;
    rawstd_uuid_to_string(&id, &s);
    return s;
}

} // namespace

// A write held by the barrier outlasts the connection's own socket timeouts
// (5 s by default) and still completes, unharmed, after the thaw.
TEST(WriteBarrierTest, a_held_write_waits_out_the_socket_timeouts) {
    rawstor::tests::ObjectEnv env(8860, 8861);
    auto queue = rawio::Queue::create(64);
    const RawstdUUID id = new_id();
    const RawstdUUID token = new_id();
    const std::string member = "ost://127.0.0.1:8861";

    rawstor::Target direct({rawstd::URI(rawstd::URI(member), id_string(id))});
    // The same member, bound to the version being taken.
    rawstor::Target bound(
        {rawstd::URI(member + "/" + id_string(id) + "/0/" + id_string(token))}
    );

    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, direct.create(*queue, spec));
    auto writer = run(*queue, direct.open(*queue, 0));

    run(*queue, bound.freeze(*queue, std::chrono::seconds(60)));

    std::vector<char> data(4096, 'x');
    rawstd::Task<size_t> write =
        writer->pwrite(data.data(), data.size(), 0, false);
    EXPECT_FALSE(run_for(*queue, write, 7000))
        << "a write was answered while its member was frozen";

    run(*queue, bound.thaw(*queue));
    ASSERT_TRUE(run_for(*queue, write, 10000));
    EXPECT_EQ(write.get(), data.size());

    // Nothing was degraded or retried away: the writer still works.
    EXPECT_EQ(
        run(*queue, writer->pwrite(data.data(), data.size(), 0, true)),
        data.size()
    );

    run(*queue, writer->close());
    run(*queue, direct.remove(*queue));
}
