#include "client.hpp"
#include "queue.hpp"
#include "tmp_dir.hpp"

#include <ost/client.hpp>
#include <ost/server.hpp>

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/socket.h>
#include <rawstd/uuid.h>

#include <sys/socket.h>

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <string>
#include <thread>

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

// A Client needs a real Server for locations(), but not its listening
// socket or accept loop -- port 0 leaves that socket bound but otherwise
// unused (the OS picks it, so there's no fixed-port collision risk
// either). The other half of the
// pair, wired directly into Client::create() below, stands in for what
// Server::_add_client() would otherwise do with a real accept()ed fd.
std::pair<std::shared_ptr<rawstor::ostbackend::Client>, int>
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

    std::shared_ptr<rawstor::ostbackend::Client> session =
        rawstor::ostbackend::Client::create(queue, server, fds[0]).get();
    return {session, fds[1]};
}

// RAII wrapper around the Client connect_session() returns: drops it and
// drains `queue` until idle before letting the destructor run, rather than
// just letting the shared_ptr go out of scope on its own. Client::_arm_recv()
// hands its multishot recv registration a heap-allocated weak_ptr<Client>
// as callback data, freed only once that registration's terminal completion
// (self-termination or the cancellation ~Client() triggers) is actually
// dispatched -- one still in flight when `queue` gets torn down right after
// is exactly what LeakSanitizer reports as a leak. Runs via RAII, not
// "cleanup code at the end of the test", so it still happens even if an
// ASSERT_* returns from the test body early.
class SessionCleanup final {
private:
    std::shared_ptr<rawstor::ostbackend::Client> _session;
    RawIOQueue* _queue;

public:
    SessionCleanup(
        std::shared_ptr<rawstor::ostbackend::Client> session, RawIOQueue* queue
    ) :
        _session(std::move(session)),
        _queue(queue) {}
    SessionCleanup(const SessionCleanup&) = delete;
    SessionCleanup(SessionCleanup&&) = delete;

    ~SessionCleanup() {
        _session.reset();
        unsigned int idle = 0;
        for (unsigned int elapsed_ms = 0; elapsed_ms < 2000 && idle < 5;
             elapsed_ms += 20) {
            int res = rawio_wait_timeout(_queue, 20);
            if (res < 0 && res != -ETIME) {
                break;
            }
            idle = (res == -ETIME) ? idle + 1 : 0;
        }
    }

    SessionCleanup& operator=(const SessionCleanup&) = delete;
    SessionCleanup& operator=(SessionCleanup&&) = delete;

    rawstor::ostbackend::Client* operator->() const noexcept {
        return _session.get();
    }
};

} // namespace

TEST(OstSessionTest, simple_success) {
    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(256, "127.0.0.1", 0, dir.uri().c_str());

    rawstor::ostbackend::tests::Queue queue;
    auto [raw_session, client_fd] = connect_session(server, queue);
    SessionCleanup session(std::move(raw_session), queue);
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

TEST(OstSessionTest, set_object_twice_does_not_crash) {
    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(256, "127.0.0.1", 0, dir.uri().c_str());

    rawstor::ostbackend::tests::Queue queue;
    auto [raw_session, client_fd] = connect_session(server, queue);
    SessionCleanup session(std::move(raw_session), queue);
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

    // First SET_OBJECT: the session's _object starts null, so this only
    // exercises rawstor_target_open() (same as simple_success above).
    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);

    // Second SET_OBJECT on the same session: _object is already set, so
    // the server's Client::_set_object() first closes it (via
    // Client::_close_current_object(), asynchronously -- rawstor_object_close()
    // queues the close and returns immediately, deferring the actual
    // open-a-new-object work to its own completion callback) before
    // opening again. This used to be where a nested run()-pumped
    // synchronous close from *inside* the server's own already-executing
    // Queue::_dispatch() call (the one dispatching this very SET_OBJECT
    // frame's completion) caused an ASan-confirmed heap-use-after-free (a
    // RecvMultishotCompletion the still-in-progress outer iteration needed
    // got freed by the reentrant inner one first); staying fully async
    // end-to-end here avoids ever reentering _dispatch() in the first
    // place, so this must still complete cleanly.
    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorOSTFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);
}

// Regression test for the heap-use-after-free ASan caught in CI (built off
// commit d023d65, ost/src/session.cpp:154, fixed by 1c260e1): a peer
// disconnect terminates the session's already-armed multishot recv with
// EPIPE (BufferRing::operator(), librawio/src/uring_buffer.cpp synthesizes
// it for a 0-byte/EOF recv) -- same as any other terminal error, not just
// ECANCELED. If that terminal completion is already sitting in the
// completion queue, unprocessed, by the time the Client is destroyed,
// ~Client()'s rawio_cancel() has nothing left to cancel (-ENOENT) and the
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
//
// Each iteration drains right after session.reset() -- not just for
// timing, but because skipping it entirely (an earlier version of this
// test did, to give draining a single generous pass at the end instead)
// starved the poll backend's completion queue (librawio/src/poll_queue.hpp's
// _cqes, a fixed-capacity rawstd::RingBuf sized to the Queue's `depth`) of
// ever being serviced across all 100 iterations. Once _cqes fills up,
// RingBuf::push() throws ENOBUFS from inside rawio_cancel() itself, so the
// cancel never completes and that session's registration -- and the
// weak_ptr<Client> its callback data owns (_arm_recv()) -- is orphaned
// for good; no amount of draining afterwards recovers from a cancel that
// already failed. CI's asan job (--without-liburing) caught exactly this,
// twice, as a LeakSanitizer failure even after the drain-more-at-the-end
// attempt.
TEST(OstSessionTest, disconnect_races_session_destruction) {
    constexpr unsigned int iterations = 100;

    rawstor::ostbackend::tests::TmpDir dir;
    rawstor::ostbackend::Server server(256, "127.0.0.1", 0, dir.uri().c_str());
    rawstor::ostbackend::tests::Queue queue;

    for (unsigned int i = 0; i < iterations; ++i) {
        auto [session, client_fd] = connect_session(server, queue);

        // Disconnect: closing the client's end terminates the session's
        // already-armed recv with EPIPE once the kernel gets to it.
        {
            rawstor::ostbackend::tests::Client client(client_fd);
        }

        // Give the kernel a chance to actually post that terminal
        // completion into the queue before the next line runs, without
        // ever draining it ourselves -- the window ~Client() must cope
        // with.
        std::this_thread::sleep_for(std::chrono::milliseconds(2));

        // Drop the only owning shared_ptr: ~Client() runs here,
        // synchronously, calling rawio_cancel() on a registration that
        // may have already self-terminated (-ENOENT, "too late").
        session.reset();

        // Service whatever's ready so far. If the terminal completion was
        // already queued before session.reset() ran above, this is where
        // the old code dereferenced freed memory; the fixed code's
        // weak_ptr::lock() just no-ops. Just as importantly, this keeps
        // the poll backend's completion queue from filling up over 100
        // iterations -- see the comment above the test for what happens
        // if it does.
        int res = rawio_wait_timeout(queue, 5);
        ASSERT_TRUE(res >= 0 || res == -ETIME);
    }

    // Catch-all for any stragglers the per-iteration drains above didn't
    // happen to catch (the kernel/backend can still take a little longer
    // than one 5ms wait to actually deliver a given completion). Stop
    // once a few consecutive waits come back empty rather than always
    // burning the full budget.
    unsigned int idle = 0;
    for (unsigned int elapsed_ms = 0; elapsed_ms < 2000 && idle < 5;
         elapsed_ms += 20) {
        int res = rawio_wait_timeout(queue, 20);
        ASSERT_TRUE(res >= 0 || res == -ETIME);
        idle = (res == -ETIME) ? idle + 1 : 0;
    }
}
