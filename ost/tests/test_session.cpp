#include "client.hpp"

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
#include <filesystem>
#include <functional>
#include <sstream>
#include <string>

#include <cerrno>

namespace {

// A fresh, uniquely-named temporary directory, removed (recursively) when
// the instance is destroyed -- so a file:// Server under test never
// shares, and can't be polluted by or race against, another test's
// on-disk location. (Deliberately not reusing tests/tmp_dir.hpp: this
// binary doesn't otherwise link anything from tests/, and duplicating
// fifteen lines beats pulling in a cross-directory source dependency for
// them.)
class TmpDir final {
private:
    std::filesystem::path _path;

public:
    TmpDir() {
        std::string tmpl =
            (std::filesystem::temp_directory_path() / "rawstor-ost-test-XXXXXX")
                .string();
        if (mkdtemp(tmpl.data()) == nullptr) {
            RAWSTD_THROW_ERRNO();
        }
        _path = tmpl;
    }

    TmpDir(const TmpDir&) = delete;
    TmpDir(TmpDir&&) = delete;

    ~TmpDir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }

    TmpDir& operator=(const TmpDir&) = delete;
    TmpDir& operator=(TmpDir&&) = delete;

    std::string uri() const {
        std::ostringstream oss;
        oss << "file://" << _path.string();
        return oss.str();
    }
};

// Owns a rawio queue for the lifetime of a test, and drives it.
class Queue final {
private:
    RawIOQueue* _queue;

public:
    Queue() : _queue(nullptr) {
        int res = rawio_queue_create(256, &_queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }

    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;

    ~Queue() { rawio_queue_delete(_queue); }

    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;

    operator RawIOQueue*() noexcept { return _queue; }
};

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

// A Session needs a real Server for locations()/write_throttle_limit(),
// but not its listening socket or accept loop -- port 0 leaves that
// socket bound but otherwise unused (the OS picks it, so there's no
// fixed-port collision risk either). The other half of the pair, wired
// directly into Session::create() below, stands in for what
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

    std::shared_ptr<rawstor::ostbackend::Session> session =
        rawstor::ostbackend::Session::create(queue, server, fds[0]);
    return {session, fds[1]};
}

} // namespace

TEST(OstSessionTest, simple_success) {
    TmpDir dir;
    rawstor::ostbackend::Server server(
        256, 128, "127.0.0.1", 0, dir.uri().c_str()
    );

    Queue queue;
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
    constexpr unsigned int kLimit = 4;
    constexpr unsigned int kWrites = 20;

    TmpDir dir;
    rawstor::ostbackend::Server server(
        256, kLimit, "127.0.0.1", 0, dir.uri().c_str()
    );

    Queue queue;
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
    for (unsigned int i = 0; i < kWrites; ++i) {
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
                   kWrites * sizeof(RawstorOSTFrameResponse);
        },
        10000
    ));

    // The invariant write-throttle-limit exists for: no matter how
    // pumping happened to batch things, the session never had more than
    // the configured cap of writes dispatched to storage at once.
    EXPECT_LE(peak_in_flight, kLimit);
    // And it wasn't just coincidentally low: with 20 writes fired at a
    // cap of 4, the session must have actually hit the cap at some
    // point, or nothing here was throttled at all.
    EXPECT_EQ(peak_in_flight, kLimit);

    for (unsigned int i = 0; i < kWrites; ++i) {
        RawstorOSTFrameResponse response = client.recv_response();
        EXPECT_EQ(response.head.cmd, RAWSTOR_CMD_WRITE);
        EXPECT_EQ(response.body.res, static_cast<int32_t>(payload.size()));
    }
}
