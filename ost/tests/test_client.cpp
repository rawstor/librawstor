#include "client.hpp"
#include "queue.hpp"
#include "tmp_dir.hpp"

#include <ost/client.hpp>
#include <ost/server.hpp>

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>
#include <rawstor/target.h>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/socket.h>
#include <rawstd/uuid.h>

#include <sys/socket.h>

#include <gtest/gtest.h>

#include <cerrno>

#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

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
std::pair<std::shared_ptr<rawstor::ostserver::Client>, int>
connect_client(rawstor::ostserver::Server& server, RawIOQueue* queue) {
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

    std::shared_ptr<rawstor::ostserver::Client> client =
        rawstor::ostserver::Client::create(queue, server, fds[0]).get();
    return {client, fds[1]};
}

// RAII wrapper around the Client connect_client() returns: drops it and
// drains `queue` until idle before letting the destructor run, rather than
// just letting the shared_ptr go out of scope on its own. Client::_arm_recv()
// hands its multishot recv registration a heap-allocated weak_ptr<Client>
// as callback data, freed only once that registration's terminal completion
// (self-termination or the cancellation ~Client() triggers) is actually
// dispatched -- one still in flight when `queue` gets torn down right after
// is exactly what LeakSanitizer reports as a leak. Runs via RAII, not
// "cleanup code at the end of the test", so it still happens even if an
// ASSERT_* returns from the test body early.
class ClientCleanup final {
private:
    std::shared_ptr<rawstor::ostserver::Client> _client;
    RawIOQueue* _queue;

public:
    ClientCleanup(
        std::shared_ptr<rawstor::ostserver::Client> client, RawIOQueue* queue
    ) :
        _client(std::move(client)),
        _queue(queue) {}
    ClientCleanup(const ClientCleanup&) = delete;
    ClientCleanup(ClientCleanup&&) = delete;

    ~ClientCleanup() {
        _client.reset();
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

    ClientCleanup& operator=(const ClientCleanup&) = delete;
    ClientCleanup& operator=(ClientCleanup&&) = delete;

    rawstor::ostserver::Client* operator->() const noexcept {
        return _client.get();
    }
};

} // namespace

TEST(OstClientTest, simple_success) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());

    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    // ALLOCATE: creates the object file:// will open next.
    client.send_allocate(id, 4096, 1);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    RawstorFrameResponse response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_ALLOCATE);
    EXPECT_EQ(response.body.res, 0);

    // SET_OBJECT: opens it for this client's subsequent READ/WRITE.
    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);

    // WRITE, then READ the same bytes back.
    std::string payload = "ping";
    client.send_write(0, payload.data(), payload.size(), false);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
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
               sizeof(RawstorFrameResponse) + payload.size();
    }));
    std::string read_back(payload.size(), '\0');
    response = client.recv_response(read_back.data(), read_back.size());
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_READ);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
    EXPECT_EQ(read_back, payload);
}

TEST(OstClientTest, discard_and_write_zeroes) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());

    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    // ALLOCATE: creates the object file:// will open next.
    client.send_allocate(id, 4096, 1);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    RawstorFrameResponse response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_ALLOCATE);
    EXPECT_EQ(response.body.res, 0);

    // SET_OBJECT: opens it for this client's subsequent WRITE/DISCARD/
    // WRITE_ZEROES/READ.
    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);

    // WRITE some non-zero bytes...
    std::string payload(64, 'x');
    client.send_write(0, payload.data(), payload.size(), false);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_WRITE);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));

    // ...WRITE_ZEROES half of it, durably...
    client.send_write_zeroes(
        0, static_cast<uint32_t>(payload.size() / 2), /*unmap=*/false,
        /*sync=*/true
    );
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_WRITE_ZEROES);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size() / 2));

    // ...and READ it back to confirm the first half reads as zero while
    // the second half still holds the original payload.
    client.send_read(0, static_cast<uint32_t>(payload.size()));
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >=
               sizeof(RawstorFrameResponse) + payload.size();
    }));
    std::string read_back(payload.size(), '\xff');
    response = client.recv_response(read_back.data(), read_back.size());
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_READ);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
    EXPECT_EQ(
        read_back.substr(0, payload.size() / 2),
        std::string(payload.size() / 2, '\0')
    );
    EXPECT_EQ(
        read_back.substr(payload.size() / 2), payload.substr(payload.size() / 2)
    );

    // DISCARD is purely advisory -- just confirm it completes successfully
    // and reports the requested size back.
    client.send_discard(0, static_cast<uint32_t>(payload.size()));
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_DISCARD);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
}

TEST(OstClientTest, set_object_twice_does_not_crash) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());

    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    // ALLOCATE: creates the object file:// will open next.
    client.send_allocate(id, 4096, 1);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    RawstorFrameResponse response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_ALLOCATE);
    EXPECT_EQ(response.body.res, 0);

    // First SET_OBJECT: the client's _object starts null, so this only
    // exercises rawstor_target_open() (same as simple_success above).
    client.send_set_object(id);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);

    // Second SET_OBJECT on the same client: _object is already set, so
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
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    response = client.recv_response();
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_SET_OBJECT);
    EXPECT_EQ(response.body.res, 0);
}

// A command code the server doesn't recognize is answered with -ENOSYS
// instead of a bare disconnect, so a client can tell "unsupported" apart
// from a transport failure -- but RawstorFrameHead carries no length
// field, so the server has no way to know how many payload bytes this
// unrecognized request's body holds, to skip past and resynchronize with
// whatever request might follow it on the wire. It closes the connection
// right after answering, so this checks both halves: the -ENOSYS response
// itself, and that the connection is then actually torn down rather than
// left open waiting for a request body that will never make sense.
TEST(OstClientTest, unknown_command_answers_enosys_then_closes) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());

    rawstor::ostserver::tests::Queue queue;
    auto [server_client, client_fd] = connect_client(server, queue);
    rawstor::ostserver::tests::Client client(client_fd);

    uint16_t cid = client.send_unknown_command();
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    RawstorFrameResponse response = client.recv_response();
    EXPECT_EQ(response.head.cid, cid);
    EXPECT_EQ(response.body.res, -ENOSYS);

    // Server::del_client() only closes the connection right away if the
    // handler's own reference was the last one outstanding (its own
    // use_count() == 1 check, server.cpp) -- true in production, where
    // nothing else keeps a Client alive, but not here as long as this
    // test also holds `server_client`. Dropping it plays the part the
    // accept loop's own shared_ptr going out of scope would otherwise
    // play, so what's left really does exercise the server's close path
    // rather than this test's own bookkeeping.
    server_client.reset();

    ASSERT_TRUE(pump_until(queue, [&] {
        char buf;
        ssize_t res = ::recv(client_fd, &buf, sizeof(buf), MSG_DONTWAIT);
        return res == 0 || (res == -1 && errno != EAGAIN);
    }));

    // Drain anything still in flight before `queue` itself is torn down at
    // end of scope -- same reason ClientCleanup's destructor does this
    // elsewhere in this file: an in-flight multishot recv registration
    // freed out from under a still-pending completion is exactly what
    // LeakSanitizer would otherwise catch.
    unsigned int idle = 0;
    for (unsigned int elapsed_ms = 0; elapsed_ms < 2000 && idle < 5;
         elapsed_ms += 20) {
        int res = rawio_wait_timeout(queue, 20);
        ASSERT_TRUE(res >= 0 || res == -ETIME);
        idle = (res == -ETIME) ? idle + 1 : 0;
    }
}

// Regression test for the heap-use-after-free ASan caught in CI (built off
// commit d023d65, ost/src/session.cpp:154, fixed by 1c260e1): a peer
// disconnect terminates the client's already-armed multishot recv with
// EPIPE (BufferRing::operator(), librawio/src/uring_buffer.cpp synthesizes
// it for a 0-byte/EOF recv) -- same as any other terminal error, not just
// ECANCELED. If that terminal completion is already sitting in the
// completion queue, unprocessed, by the time the Client is destroyed,
// ~Client()'s rawio_cancel() has nothing left to cancel (-ENOENT) and the
// completion still fires later, into what used to be a raw `this` pointer.
//
// Whether the kernel has actually posted that completion by the time
// server_client.reset() below runs is real scheduling timing, not something
// this test controls directly -- the short sleep after disconnect just
// biases the odds toward "already posted", and looping raises the odds of
// hitting that window at least once per run; neither guarantees it (600
// ASan repeats of the pre-fix suite never reproduced this locally either,
// per 1c260e1's commit message). This test's teeth are under --enable-asan
// (as CI's asan job builds), same as how the original bug was only ever
// caught there: on the pre-fix code, enough iterations reliably abort the
// process; on the fixed code, weak_ptr::lock() just no-ops and the loop
// completes.
//
// Each iteration drains right after server_client.reset() -- not just for
// timing, but because skipping it entirely (an earlier version of this
// test did, to give draining a single generous pass at the end instead)
// starved the poll backend's completion queue (librawio/src/poll_queue.hpp's
// _cqes, a fixed-capacity rawstd::RingBuf sized to the Queue's `depth`) of
// ever being serviced across all 100 iterations. Once _cqes fills up,
// RingBuf::push() throws ENOBUFS from inside rawio_cancel() itself, so the
// cancel never completes and that client's registration -- and the
// weak_ptr<Client> its callback data owns (_arm_recv()) -- is orphaned
// for good; no amount of draining afterwards recovers from a cancel that
// already failed. CI's asan job (--without-liburing) caught exactly this,
// twice, as a LeakSanitizer failure even after the drain-more-at-the-end
// attempt.
TEST(OstClientTest, disconnect_races_client_destruction) {
    constexpr unsigned int iterations = 100;

    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());
    rawstor::ostserver::tests::Queue queue;

    for (unsigned int i = 0; i < iterations; ++i) {
        auto [server_client, client_fd] = connect_client(server, queue);

        // Disconnect: closing the client's end terminates the server-side
        // client's already-armed recv with EPIPE once the kernel gets to
        // it.
        {
            rawstor::ostserver::tests::Client client(client_fd);
        }

        // Give the kernel a chance to actually post that terminal
        // completion into the queue before the next line runs, without
        // ever draining it ourselves -- the window ~Client() must cope
        // with.
        std::this_thread::sleep_for(std::chrono::milliseconds(2));

        // Drop the only owning shared_ptr: ~Client() runs here,
        // synchronously, calling rawio_cancel() on a registration that
        // may have already self-terminated (-ENOENT, "too late").
        server_client.reset();

        // Service whatever's ready so far. If the terminal completion was
        // already queued before server_client.reset() ran above, this is
        // where the old code dereferenced freed memory; the fixed code's
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

namespace {

struct CreateResult {
    bool done = false;
    ssize_t result = 0;
};

int create_cb(ssize_t result, void* data) {
    CreateResult* r = static_cast<CreateResult*>(data);
    r->result = result;
    r->done = true;
    return 0;
}

} // namespace

// A multi-chunk object -- two chunks of the same id, at offset 0 and a
// second, non-adjacent offset -- must come back over the wire as one row
// per offset (RawstorFrameListEntry's own doc comment, protocol.h),
// not just its first chunk's own offset repeated or dropped.
TEST(OstClientTest, list_reports_every_chunk_offset) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());

    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    RawstdUUIDString id_str;
    rawstd_uuid_to_string(&id, &id_str);

    const uint64_t second_offset = 1ull << 20;
    char offset_hex[17];
    std::snprintf(offset_hex, sizeof(offset_hex), "%" PRIx64, second_offset);

    std::string target0 = dir.uri() + "/" + id_str + "/0";
    std::string target1 =
        dir.uri() + "/" + std::string(id_str) + "/" + offset_hex;

    RawstorObjectSpec spec{
        .size = 4096,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };

    CreateResult res0;
    int rc =
        rawstor_target_create(queue, target0.c_str(), &spec, create_cb, &res0);
    ASSERT_GE(rc, 0);
    ASSERT_TRUE(pump_until(queue, [&] { return res0.done; }));
    ASSERT_EQ(res0.result, 0);

    CreateResult res1;
    rc = rawstor_target_create(queue, target1.c_str(), &spec, create_cb, &res1);
    ASSERT_GE(rc, 0);
    ASSERT_TRUE(pump_until(queue, [&] { return res1.done; }));
    ASSERT_EQ(res1.result, 0);

    RawstdUUID token{};
    client.send_list(token, 16);

    // Two real rows (one per offset) plus the trailing resume cursor.
    const size_t expected_rows = 3;
    const size_t payload_size = expected_rows * sizeof(RawstorFrameListEntry);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >=
               sizeof(RawstorFrameResponse) + payload_size;
    }));
    std::vector<RawstorFrameListEntry> entries(expected_rows);
    RawstorFrameResponse response =
        client.recv_response(entries.data(), payload_size);
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_LIST);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(payload_size));

    RawstdUUID row_id;
    std::memcpy(row_id.bytes, entries[0].id, sizeof(row_id.bytes));
    EXPECT_EQ(rawstd_uuid_cmp(&row_id, &id), 0);
    EXPECT_EQ(entries[0].chunk_offset, 0u);

    std::memcpy(row_id.bytes, entries[1].id, sizeof(row_id.bytes));
    EXPECT_EQ(rawstd_uuid_cmp(&row_id, &id), 0);
    EXPECT_EQ(entries[1].chunk_offset, second_offset);

    // The last row is always the resume cursor -- nil here, since nothing
    // was left after this one id (RawstorPaginationToken's own doc
    // comment, rawstor.h: a nil id means "from the start").
    RawstdUUID nil_id{};
    std::memcpy(row_id.bytes, entries[2].id, sizeof(row_id.bytes));
    EXPECT_EQ(rawstd_uuid_cmp(&row_id, &nil_id), 0);
}

namespace {

RawstorObjectSyncStateValue stored_state(
    RawIOQueue* queue, const std::string& location, const RawstdUUID& id
) {
    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);
    std::string target = location + "/" + id_string;

    RawstorObjectMeta meta{};
    bool done = false;
    ssize_t result = 0;
    struct Ctx {
        bool* done;
        ssize_t* result;
    } ctx{&done, &result};
    int res = rawstor_target_meta(
        queue, target.c_str(), 0, &meta, 1,
        [](ssize_t r, void* data) {
            Ctx* c = static_cast<Ctx*>(data);
            *c->result = r;
            *c->done = true;
            return 0;
        },
        &ctx
    );
    EXPECT_EQ(res, 0);
    EXPECT_TRUE(pump_until(queue, [&] { return done; }));
    EXPECT_GE(result, 0);
    return meta.state;
}

void write_and_wait(
    rawstor::ostserver::tests::Client& client, RawIOQueue* queue
) {
    std::string payload = "ping";
    client.send_write(0, payload.data(), payload.size(), false);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    ASSERT_EQ(
        client.recv_response().body.res, static_cast<int32_t>(payload.size())
    );
}

} // namespace

// A session's LEAVE closes its object cleanly, and the copy goes CLEAN
// once no session open for writing is left; a session that wrote and
// whose connection drops without one leaves the copy LOST
// (docs/mirroring.md, "DIRTY, CLEAN and LOST").
TEST(OstClientTest, leave_cleans_and_a_dropped_writer_loses) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());
    rawstor::ostserver::tests::Queue queue;

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);

    {
        auto [raw_client, client_fd] = connect_client(server, queue);
        ClientCleanup server_client(std::move(raw_client), queue);
        rawstor::ostserver::tests::Client client(client_fd);

        client.send_allocate(id, 4096, 1);
        ASSERT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >= sizeof(RawstorFrameResponse);
        }));
        ASSERT_EQ(client.recv_response().body.res, 0);

        client.send_set_object(id);
        ASSERT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >= sizeof(RawstorFrameResponse);
        }));
        ASSERT_EQ(client.recv_response().body.res, 0);

        write_and_wait(client, queue);
        EXPECT_EQ(
            stored_state(queue, dir.uri(), id), RAWSTOR_OBJECT_SYNC_STATE_DIRTY
        );

        client.send_leave();
        ASSERT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >= sizeof(RawstorFrameResponse);
        }));
        RawstorFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_LEAVE);
        EXPECT_EQ(response.body.res, 0);
        EXPECT_EQ(
            stored_state(queue, dir.uri(), id), RAWSTOR_OBJECT_SYNC_STATE_CLEAN
        );
    }

    {
        auto [raw_client, client_fd] = connect_client(server, queue);
        ClientCleanup server_client(std::move(raw_client), queue);
        {
            rawstor::ostserver::tests::Client client(client_fd);
            client.send_set_object(id);
            ASSERT_TRUE(pump_until(queue, [&] {
                return client.bytes_available() >= sizeof(RawstorFrameResponse);
            }));
            ASSERT_EQ(client.recv_response().body.res, 0);
            write_and_wait(client, queue);
        }
        // The client's end is closed without a LEAVE.
    }
    // The server's Client goes away with the connection, closing the
    // object it set as an unclean departure.
    EXPECT_EQ(
        stored_state(queue, dir.uri(), id), RAWSTOR_OBJECT_SYNC_STATE_LOST
    );
}

// A server with several locations is still one copy to its clients, but
// keeps no record of that copy: the locations' records belong to its own
// mirror of them. It answers SET_CONFIG with -ENOSYS and reports no sync
// identity (docs/mirroring.md, "One copy per server").
TEST(OstClientTest, several_locations_keep_no_record_of_the_copy) {
    rawstor::ostserver::tests::TmpDir a;
    rawstor::ostserver::tests::TmpDir b;
    std::string locations = a.uri() + "," + b.uri();
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, locations.c_str());
    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    auto expect_response = [&](RawstorCommandType cmd, int32_t res) {
        ASSERT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >= sizeof(RawstorFrameResponse);
        }));
        RawstorFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, cmd);
        EXPECT_EQ(response.body.res, res);
    };

    client.send_allocate(id, 4096, 2);
    expect_response(RAWSTOR_CMD_ALLOCATE, 0);

    RawstorFrameSetConfig set{};
    std::memcpy(set.payload.object_id, id.bytes, sizeof(id.bytes));
    set.payload.config.epoch = 3;
    set.payload.config.sync_id = 0x33;
    client.send_set_config(set);
    expect_response(RAWSTOR_CMD_SET_CONFIG, -ENOSYS);

    RawstorFrameSyncPropose prepare{};
    prepare.head.cmd = RAWSTOR_CMD_SYNC_PREPARE;
    std::memcpy(prepare.payload.object_id, id.bytes, sizeof(id.bytes));
    prepare.payload.ballot = {1, 1};
    client.send_sync(prepare);
    expect_response(RAWSTOR_CMD_SYNC_PREPARE, -ENOSYS);

    // No copy of its own to fence a stamped write on, or to tell a RESYNC
    // write which sectors to skip.
    client.send_set_object(id);
    expect_response(RAWSTOR_CMD_SET_OBJECT, 0);
    std::string ping = "ping";
    client.send_write_at_epoch(0, ping.data(), ping.size(), 1);
    expect_response(RAWSTOR_CMD_WRITE, -EOPNOTSUPP);
    client.send_write_at_epoch(
        0, ping.data(), ping.size(), 0, RAWSTOR_FLAG_RESYNC
    );
    expect_response(RAWSTOR_CMD_WRITE, -EOPNOTSUPP);
    client.send_write_at_epoch(0, ping.data(), ping.size(), 0);
    expect_response(RAWSTOR_CMD_WRITE, static_cast<int32_t>(ping.size()));

    client.send_meta(id, 0);
    RawstorFrameMetaPayload meta{};
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >=
               sizeof(RawstorFrameResponse) + sizeof(meta);
    }));
    RawstorFrameResponse response = client.recv_response(&meta, sizeof(meta));
    EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_META);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(sizeof(meta)));
    EXPECT_EQ(meta.size, 4096u);
    EXPECT_EQ(meta.config.epoch, 0u);
    EXPECT_EQ(meta.config.sync_id, 0u);
    EXPECT_EQ(meta.config.nroles, 0);
}

namespace {

RawstorFrameSyncPropose sync_frame(
    RawstorCommandType cmd, const RawstdUUID& id, uint64_t counter,
    uint64_t proposer
) {
    RawstorFrameSyncPropose frame{};
    frame.head.cmd = cmd;
    std::memcpy(frame.payload.object_id, id.bytes, sizeof(id.bytes));
    frame.payload.ballot = {counter, proposer};
    return frame;
}

RawstorFrameSyncReplyPayload sync_round_trip(
    rawstor::ostserver::tests::Client& client, RawIOQueue* queue,
    const RawstorFrameSyncPropose& frame
) {
    client.send_sync(frame);
    RawstorFrameSyncReplyPayload reply{};
    EXPECT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >=
               sizeof(RawstorFrameResponse) + sizeof(reply);
    }));
    RawstorFrameResponse response = client.recv_response(&reply, sizeof(reply));
    EXPECT_EQ(response.head.cmd, frame.head.cmd);
    EXPECT_EQ(response.body.res, static_cast<int32_t>(sizeof(reply)));
    return reply;
}

} // namespace

// The copy's record as a register acceptor (docs/multiattach.md, "The
// register"): rawstor-ost applies the rawstd::caspaxos rules to its copy's
// record and replies with that record whether the request succeeded or
// not.
TEST(OstClientTest, sync_register_promises_and_accepts) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());

    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    client.send_allocate(id, 4096, 1);
    ASSERT_TRUE(pump_until(queue, [&] {
        return client.bytes_available() >= sizeof(RawstorFrameResponse);
    }));
    ASSERT_EQ(client.recv_response().body.res, 0);

    RawstorFrameSyncReplyPayload reply = sync_round_trip(
        client, queue, sync_frame(RAWSTOR_CMD_SYNC_PREPARE, id, 2, 7)
    );
    EXPECT_EQ(reply.ok, 1);
    EXPECT_EQ(reply.meta.promised.counter, 2u);
    EXPECT_EQ(reply.meta.promised.proposer, 7u);
    EXPECT_EQ(reply.meta.accepted.counter, 0u);

    // A lower ballot is refused, and the reply shows the promise that
    // beat it.
    reply = sync_round_trip(
        client, queue, sync_frame(RAWSTOR_CMD_SYNC_PREPARE, id, 1, 9)
    );
    EXPECT_EQ(reply.ok, 0);
    EXPECT_EQ(reply.meta.promised.counter, 2u);
    EXPECT_EQ(reply.meta.promised.proposer, 7u);

    RawstorFrameSyncPropose accept =
        sync_frame(RAWSTOR_CMD_SYNC_ACCEPT, id, 2, 7);
    accept.payload.next = {3, 7};
    accept.payload.config.epoch = 5;
    accept.payload.config.sync_id = 0xabc;
    accept.payload.config.nroles = 1;
    accept.payload.config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    reply = sync_round_trip(client, queue, accept);
    EXPECT_EQ(reply.ok, 1);
    EXPECT_EQ(reply.meta.config.epoch, 5u);
    EXPECT_EQ(reply.meta.config.sync_id, 0xabcu);
    EXPECT_EQ(reply.meta.accepted.counter, 2u);
    EXPECT_EQ(reply.meta.promised.counter, 3u);
    ASSERT_EQ(reply.meta.config.nroles, 1);
    EXPECT_EQ(reply.meta.config.roles[0], RAWSTOR_OBJECT_MEMBER_IN_SYNC);

    // The same ballot again: already accepted under it, refused, and the
    // reply carries the value it holds.
    accept.payload.config.epoch = 6;
    reply = sync_round_trip(client, queue, accept);
    EXPECT_EQ(reply.ok, 0);
    EXPECT_EQ(reply.meta.config.epoch, 5u);

    // The promised next ballot goes through without a prepare.
    accept.payload.ballot = {3, 7};
    accept.payload.next = {0, 0};
    reply = sync_round_trip(client, queue, accept);
    EXPECT_EQ(reply.ok, 1);
    EXPECT_EQ(reply.meta.config.epoch, 6u);
    EXPECT_EQ(reply.meta.accepted.counter, 3u);
}

// A write stamped with an epoch below the copy's accepted configuration is
// refused with -ESTALE; one at the current epoch, or unstamped (0), goes
// through (docs/multiattach.md, "Epoch on writes").
TEST(OstClientTest, write_below_the_accepted_epoch_is_stale) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());
    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    auto expect_response = [&](RawstorCommandType cmd, int32_t res) {
        ASSERT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >= sizeof(RawstorFrameResponse);
        }));
        RawstorFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, cmd);
        EXPECT_EQ(response.body.res, res);
    };

    client.send_allocate(id, 4096, 1);
    expect_response(RAWSTOR_CMD_ALLOCATE, 0);
    client.send_set_object(id);
    expect_response(RAWSTOR_CMD_SET_OBJECT, 0);

    RawstorFrameSyncPropose accept =
        sync_frame(RAWSTOR_CMD_SYNC_ACCEPT, id, 1, 1);
    accept.payload.config.epoch = 5;
    ASSERT_EQ(sync_round_trip(client, queue, accept).ok, 1);

    std::string payload = "ping";
    client.send_write_at_epoch(0, payload.data(), payload.size(), 3);
    expect_response(RAWSTOR_CMD_WRITE, -ESTALE);
    client.send_flush_at_epoch(3);
    expect_response(RAWSTOR_CMD_FLUSH, -ESTALE);

    client.send_write_at_epoch(0, payload.data(), payload.size(), 5);
    expect_response(RAWSTOR_CMD_WRITE, static_cast<int32_t>(payload.size()));
    client.send_write_at_epoch(0, payload.data(), payload.size(), 0);
    expect_response(RAWSTOR_CMD_WRITE, static_cast<int32_t>(payload.size()));
    client.send_flush_at_epoch(5);
    expect_response(RAWSTOR_CMD_FLUSH, 0);
}

// A resync's copy onto a SYNCING member (docs/multiattach.md, "Resync
// across processes"): the copy takes its role from the configuration at
// the position the request names; a RESYNC write then lands only on the
// sectors no client write covered whole since it became SYNCING, and once
// its role is anything else a RESYNC write is refused.
TEST(OstClientTest, resync_write_skips_sectors_clients_wrote) {
    rawstor::ostserver::tests::TmpDir dir;
    int listen_fd = rawstor::ostserver::Server::bind_listen("127.0.0.1", 0);
    rawstor::ostserver::Server server(256, listen_fd, dir.uri().c_str());
    rawstor::ostserver::tests::Queue queue;
    auto [raw_client, client_fd] = connect_client(server, queue);
    ClientCleanup server_client(std::move(raw_client), queue);
    rawstor::ostserver::tests::Client client(client_fd);

    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    auto expect_response = [&](RawstorCommandType cmd, int32_t res) {
        ASSERT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >= sizeof(RawstorFrameResponse);
        }));
        RawstorFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, cmd);
        EXPECT_EQ(response.body.res, res);
    };
    // This copy is member 1 of 2; member 0 is the source of the resync.
    auto set_role = [&](RawstorObjectMemberRole role) {
        RawstorFrameSetConfig frame{};
        std::memcpy(frame.payload.object_id, id.bytes, sizeof(id.bytes));
        frame.payload.config.nroles = 2;
        frame.payload.config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
        frame.payload.config.roles[1] = role;
        frame.payload.position = 1;
        client.send_set_config(frame);
        expect_response(RAWSTOR_CMD_SET_CONFIG, 0);
    };
    auto read_all = [&](size_t size) {
        client.send_read(0, static_cast<uint32_t>(size));
        std::string ret(size, '\0');
        EXPECT_TRUE(pump_until(queue, [&] {
            return client.bytes_available() >=
                   sizeof(RawstorFrameResponse) + size;
        }));
        client.recv_response(ret.data(), ret.size());
        return ret;
    };

    client.send_allocate(id, 4096, 1);
    expect_response(RAWSTOR_CMD_ALLOCATE, 0);
    client.send_set_object(id);
    expect_response(RAWSTOR_CMD_SET_OBJECT, 0);

    // Not SYNCING yet: nothing to tell a RESYNC write what to skip.
    std::string copy(2048, 'R');
    client.send_write_at_epoch(
        0, copy.data(), copy.size(), 0, RAWSTOR_FLAG_RESYNC
    );
    expect_response(RAWSTOR_CMD_WRITE, -ESTALE);

    set_role(RAWSTOR_OBJECT_MEMBER_SYNCING);

    // Sector 1 whole, sector 2 in part.
    std::string whole(512, 'A');
    client.send_write_at_epoch(512, whole.data(), whole.size(), 0);
    expect_response(RAWSTOR_CMD_WRITE, 512);
    std::string part(2, 'B');
    client.send_write_at_epoch(1024, part.data(), part.size(), 0);
    expect_response(RAWSTOR_CMD_WRITE, 2);

    // Still SYNCING: the record of what clients wrote stays.
    set_role(RAWSTOR_OBJECT_MEMBER_SYNCING);

    client.send_write_at_epoch(
        0, copy.data(), copy.size(), 0, RAWSTOR_FLAG_RESYNC
    );
    expect_response(RAWSTOR_CMD_WRITE, 2048);

    std::string expected =
        std::string(512, 'R') + whole + std::string(1024, 'R');
    EXPECT_EQ(read_all(2048), expected);

    set_role(RAWSTOR_OBJECT_MEMBER_IN_SYNC);
    client.send_write_at_epoch(
        0, copy.data(), copy.size(), 0, RAWSTOR_FLAG_RESYNC
    );
    expect_response(RAWSTOR_CMD_WRITE, -ESTALE);
    EXPECT_EQ(read_all(2048), expected);
}
