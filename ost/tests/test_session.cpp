#include "client.hpp"
#include "queue.hpp"
#include "tmp_dir.hpp"

#include <ost/server.hpp>
#include <ost/session.hpp>

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/socket.h>
#include <rawstd/uuid.h>

#include <sys/socket.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

#include <cerrno>

namespace {

// Pumps `queue` until `done()` returns true or `budget_ms` elapses,
// calling `done()` once more right before giving up. Mirrors the
// bounded, timeout-based pump loop tests/test_io.cpp's
// OstIOTest.write_disconnect_concurrent already uses for the same
// reason: an unexpectedly orphaned op must fail the test, not hang the
// whole binary forever.
bool pump_until(
    RawIOQueue* queue, const std::function<bool()>& done,
    unsigned int budget_ms = 5000
) {
    for (unsigned int elapsed_ms = 0; elapsed_ms < budget_ms;
         elapsed_ms += 20) {
        if (done()) {
            return true;
        }
        int res = rawio_wait_timeout(queue, 20);
        if (res < 0 && res != -ETIME) {
            return false;
        }
    }
    return done();
}

// A Session needs a real Server for locations()/write_throttle_limit()/
// write_backlog_capacity(), but not its listening socket or accept loop --
// port 0 leaves that socket bound but otherwise unused (the OS picks it,
// so there's no fixed-port collision risk either). The other half of the
// pair, wired directly into Session::create() below, stands in for what
// Server::_add_session() would otherwise do with a real accept()ed fd.
std::pair<std::shared_ptr<rawstor::ostbackend::Session>, int>
connect_session(rawstor::ostbackend::Server& server, RawIOQueue* queue) {
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
        RAWSTD_THROW_ERRNO();
    }

    int res = rawstd_socket_set_nosigpipe(fds[0]);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    // A real accept()ed fd gets this for free, set internally by
    // rawio_accept_multishot()'s own setup_fd() call (both backends --
    // see e.g. librawio/src/poll_event.cpp's EventSimplexAcceptMultishot);
    // fabricating a fake "accepted" fd via socketpair() instead, bypassing
    // rawio_accept_multishot() entirely, skips that. Needed regardless: the
    // poll backend's recv_multishot loops recv() until EAGAIN to know it
    // has drained everything currently available, which a still-blocking
    // fd never delivers -- that next recv() call blocks the whole event
    // loop solid instead. io_uring doesn't care either way.
    res = rawstd_socket_set_nonblock(fds[0]);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::shared_ptr<rawstor::ostbackend::Session> session =
        rawstor::ostbackend::Session::create(queue, server, fds[0]);
    return {session, fds[1]};
}

} // namespace

TEST(OstSessionTest, simple_success) {
    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(
        256, 128, 1u << 20, "127.0.0.1", 0, dir.uri().c_str()
    );

    rawstor::ostbackend::tests::Queue queue;
    auto [session, client_fd] = connect_session(server, queue);
    (void)session;
    rawstor::ostbackend::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    // ALLOCATE: creates the object file:// will open next.
    client.send_allocate(id, 4096);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    RawstorOSTFrameResponse response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_ALLOCATE);
    EXPECT_EQ(response.body.res, 0);

    // SET_OBJECT: opens it for this session's subsequent READ/WRITE.
    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);

    // WRITE, then READ the same bytes back.
    std::string payload = "ping";
    client.send_write(0, payload.data(), payload.size(), false);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_WRITE);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
    EXPECT_EQ(
        response.body.hash, rawstd_hash_scalar(payload.data(), payload.size())
    );

    client.send_read(0, static_cast<uint32_t>(payload.size()));
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >=
               sizeof(RawstorOSTFrameResponse) + payload.size();
    }));
    std::string read_back(payload.size(), '\0');
    response = client.recv_response(read_back.data(), read_back.size());
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_READ);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
    EXPECT_EQ(read_back, payload);
}

TEST(OstSessionTest, write_throttle_limit) {
    constexpr unsigned int limit = 4;
    constexpr unsigned int writes = 20;

    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(
        256, limit, 1u << 20, "127.0.0.1", 0, dir.uri().c_str()
    );

    rawstor::ostbackend::tests::Queue queue;
    auto [session, client_fd] = connect_session(server, queue);
    rawstor::ostbackend::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    client.send_allocate(id, 1u << 20);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    ASSERT_EQ(client.recv_response().body.res, 0);

    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    ASSERT_EQ(client.recv_response().body.res, 0);

    // Fire every write back to back, without reading any response in
    // between -- exactly the pattern that, pre-write-throttle-limit, let
    // a session facing a backing store slower than the incoming write
    // rate buffer an unbounded number of writes at once.
    std::string payload = "throttle-me";
    for (unsigned int i = 0; i < writes; ++i) {
        client.send_write(
            i * payload.size(), payload.data(), payload.size(), false
        );
    }

    // Sampled after every pump above (see pump_until()): however many
    // completions any single rawio_wait_timeout() call happened to
    // batch, this is the most writes the session ever had dispatched to
    // storage at once.
    unsigned int peak_in_flight = 0;
    ASSERT_TRUE(pump_until(
        queue,
        [&] {
            peak_in_flight =
                std::max(peak_in_flight, session->writes_in_flight());
            return client.bytes_available() >=
                   writes * sizeof(RawstorOSTFrameResponse);
        },
        10000
    ));

    // The invariant write-throttle-limit exists for: no matter how
    // pumping happened to batch things, the session never had more than
    // the configured cap of writes dispatched to storage at once.
    EXPECT_LE(peak_in_flight, limit);
    // And it wasn't just coincidentally low: with 20 writes fired at a
    // cap of 4, the session must have actually hit the cap at some
    // point, or nothing here was throttled at all.
    EXPECT_EQ(peak_in_flight, limit);

    for (unsigned int i = 0; i < writes; ++i) {
        RawstorOSTFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_WRITE);
        EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
    }
}

TEST(OstSessionTest, write_backlog_capacity) {
    // A throttle-limit of 1 puts every write from the second one onward on
    // the backlog check's path immediately, without waiting on real
    // storage-completion timing to get there.
    constexpr unsigned int throttle_limit = 1;
    const std::string payload(16, 'x');
    const size_t backlog_capacity = payload.size() * 3;
    constexpr unsigned int writes = 50;

    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(
        256, throttle_limit, backlog_capacity, "127.0.0.1", 0, dir.uri().c_str()
    );

    rawstor::ostbackend::tests::Queue queue;
    auto [session, client_fd] = connect_session(server, queue);
    rawstor::ostbackend::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    client.send_allocate(id, 1u << 20);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    ASSERT_EQ(client.recv_response().body.res, 0);

    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    ASSERT_EQ(client.recv_response().body.res, 0);

    // Fire every write back to back, without reading any response in
    // between, so the whole burst is already sitting in the kernel's
    // socket buffer before the session is pumped even once -- exactly the
    // scenario that would let an already-throttled session's pending-write
    // backlog grow without bound if nothing capped it.
    for (unsigned int i = 0; i < writes; ++i) {
        client.send_write(
            i * payload.size(), payload.data(), payload.size(), false
        );
    }

    size_t peak_pending_bytes = 0;
    ASSERT_TRUE(pump_until(
        queue,
        [&] {
            peak_pending_bytes =
                std::max(peak_pending_bytes, session->pending_writes_bytes());
            return client.bytes_available() >=
                   writes * sizeof(RawstorOSTFrameResponse);
        },
        10000
    ));

    // The invariant write-backlog-capacity exists for: the backlog never grew
    // past the configured cap...
    EXPECT_LE(peak_pending_bytes, backlog_capacity);
    // ...and it wasn't just coincidentally low: it must have actually
    // filled up at some point, or nothing here was capped at all.
    EXPECT_EQ(peak_pending_bytes, backlog_capacity);

    unsigned int accepted = 0;
    unsigned int rejected = 0;
    for (unsigned int i = 0; i < writes; ++i) {
        RawstorOSTFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_WRITE);
        if (response.body.res == static_cast<int32_t>(payload.size())) {
            ++accepted;
        } else {
            EXPECT_EQ(response.body.res, -EBUSY);
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

// Regression test for the heap-use-after-free ASan caught in CI (built off
// commit d023d65, ost/src/session.cpp:154, fixed by 1c260e1): a peer
// disconnect terminates the session's already-armed multishot recv with
// EPIPE (BufferRing::operator(), librawio/src/uring_buffer.cpp synthesizes
// it for a 0-byte/EOF recv) -- same as any other terminal error, not just
// ECANCELED. If that terminal completion is already sitting in the
// completion queue, unprocessed, by the time the Session is destroyed,
// ~Session()'s rawio_cancel() has nothing left to cancel (-ENOENT) and the
// completion still fires later, into what used to be a raw `this` pointer.
//
// Whether the kernel has actually posted that completion by the time
// session.reset() below runs is real scheduling timing, not something this
// test controls directly -- the short sleep after disconnect just biases
// the odds toward "already posted", and looping raises the odds of hitting
// that window at least once per run; neither guarantees it (600 ASan
// repeats of the pre-fix suite never reproduced this locally either, per
// 1c260e1's commit message). This test's teeth are under --enable-asan (as
// CI's asan job builds), same as how the original bug was only ever caught
// there: on the pre-fix code, enough iterations reliably abort the process;
// on the fixed code, weak_ptr::lock() just no-ops and the loop completes.
TEST(OstSessionTest, disconnect_races_session_destruction) {
    constexpr unsigned int iterations = 100;

    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(
        256, 128, 1u << 20, "127.0.0.1", 0, dir.uri().c_str()
    );
    rawstor::ostbackend::tests::Queue queue;

    for (unsigned int i = 0; i < iterations; ++i) {
        auto [session, client_fd] = connect_session(server, queue);

        // Disconnect: closing the client's end terminates the session's
        // already-armed recv with EPIPE once the kernel gets to it.
        { rawstor::ostbackend::tests::Client client(client_fd); }

        // Give the kernel a chance to actually post that terminal
        // completion into the queue before the next line runs, without
        // ever draining it ourselves -- the window ~Session() must cope
        // with.
        std::this_thread::sleep_for(std::chrono::milliseconds(2));

        // Drop the only owning shared_ptr: ~Session() runs here,
        // synchronously, calling rawio_cancel() on a registration that
        // may have already self-terminated (-ENOENT, "too late").
        session.reset();

        // Drain whatever's left. If the terminal completion was already
        // queued before session.reset() ran above, this is where the old
        // code dereferenced freed memory; the fixed code's
        // weak_ptr::lock() just no-ops.
        for (unsigned int drain = 0; drain < 3; ++drain) {
            int res = rawio_wait_timeout(queue, 5);
            ASSERT_TRUE(res >= 0 || res == -ETIME);
        }
    }
}
