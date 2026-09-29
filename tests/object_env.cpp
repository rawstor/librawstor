#include "object_env.hpp"

#include <mds/server.hpp>

#include <ost/server.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/pipe.hpp>
#include <rawstd/uuid.h>

#include <exception>
#include <future>
#include <sstream>
#include <utility>

#include <unistd.h>

namespace rawstor {
namespace tests {

namespace {

// Runs `body` (which constructs a Server and calls its blocking loop())
// on its own thread, but only returns once the Server itself is
// constructed or construction throws -- so a construction failure (e.g.
// the MDS store failing to open) surfaces in the test's own thread
// instead of leaving it to connect to a server that never runs.
template <typename ConstructAndLoop>
std::thread spawn_server(ConstructAndLoop&& body) {
    auto ready = std::make_shared<std::promise<void>>();
    std::future<void> ready_future = ready->get_future();
    std::thread t([body = std::forward<ConstructAndLoop>(body),
                   ready]() mutable { body(ready); });
    ready_future.get();
    return t;
}

} // namespace

ObjectEnv::ObjectEnv(unsigned int mds_port, unsigned int ost_port) :
    _ost_listen_fd(-1),
    _ost_wake_write_fd(-1),
    _mds_listen_fd(-1),
    _mds_wake_write_fd(-1),
    _mds_port(mds_port) {
    RawstdUUID ost_id;
    int res = rawstd_uuid_from_string(
        &ost_id, "018f4e2a-0000-7000-8000-000000000001"
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::ostringstream ost_addr_oss;
    ost_addr_oss << "127.0.0.1:" << ost_port;

    mds::Topology topology;
    mds::TopologyOST ost{};
    ost.id = ost_id;
    ost.location = "ost://" + ost_addr_oss.str();
    ost.weight = 100;
    ost.path[0] = "dc1";
    ost.path[1] = "row1";
    ost.path[2] = "rack1";
    ost.path[3] = "host1";
    topology.add(ost);

    // bind_listen() happens here, on this (the test's) thread, for both
    // servers -- neither Server's own constructor binds anything itself.
    _ost_listen_fd = ostserver::Server::bind_listen("127.0.0.1", ost_port);

    rawstd::Pipe ost_wake(rawstd::Pipe::Mode::NonBlocking);
    _ost_wake_write_fd = ost_wake.release_write();
    int ost_wake_read_fd = ost_wake.release_read();

    std::string ost_location = _ost_dir.uri();
    _ost_thread = spawn_server(
        [fd = _ost_listen_fd, ost_location,
         ost_wake_read_fd](std::shared_ptr<std::promise<void>> ready) {
            try {
                ostserver::Server s(
                    256, fd, ost_location.c_str(), ost_wake_read_fd
                );
                ready->set_value();
                s.loop();
            } catch (...) {
                std::exception_ptr e = std::current_exception();
                try {
                    ready->set_exception(e);
                } catch (const std::future_error&) {
                }
            }
        }
    );

    _mds_listen_fd = mds::Server::bind_listen("127.0.0.1", mds_port);

    rawstd::Pipe mds_wake(rawstd::Pipe::Mode::NonBlocking);
    _mds_wake_write_fd = mds_wake.release_write();
    int mds_wake_read_fd = mds_wake.release_read();

    std::string mds_db = (_mds_dir.path() / "mds.db").string();
    _mds_thread = spawn_server(
        [fd = _mds_listen_fd, mds_db, topology,
         mds_wake_read_fd](std::shared_ptr<std::promise<void>> ready) mutable {
            try {
                mds::ObjectStore store(mds_db, std::move(topology));
                mds::Server s(256, fd, store, mds_wake_read_fd);
                ready->set_value();
                s.loop();
            } catch (...) {
                std::exception_ptr e = std::current_exception();
                try {
                    ready->set_exception(e);
                } catch (const std::future_error&) {
                }
            }
        }
    );
}

ObjectEnv::~ObjectEnv() {
    // Wake both loop()s -- see mds::Server/ostserver::Server's own
    // constructor doc comments: wake_fd is only ever read from, so the
    // one write byte each expects is exactly the "stop" signal
    // main.cpp's own SIGINT/SIGTERM handlers send in production.
    char byte = 0;
    if (_ost_wake_write_fd != -1) {
        ssize_t ignored = write(_ost_wake_write_fd, &byte, 1);
        (void)ignored;
    }
    if (_mds_wake_write_fd != -1) {
        ssize_t ignored = write(_mds_wake_write_fd, &byte, 1);
        (void)ignored;
    }
    if (_ost_thread.joinable()) {
        _ost_thread.join();
    }
    if (_mds_thread.joinable()) {
        _mds_thread.join();
    }
    if (_ost_wake_write_fd != -1) {
        close(_ost_wake_write_fd);
    }
    if (_mds_wake_write_fd != -1) {
        close(_mds_wake_write_fd);
    }
    if (_ost_listen_fd != -1) {
        close(_ost_listen_fd);
    }
    if (_mds_listen_fd != -1) {
        close(_mds_listen_fd);
    }
}

std::string ObjectEnv::location() const {
    std::ostringstream oss;
    oss << "mds://127.0.0.1:" << _mds_port;
    return oss.str();
}

} // namespace tests
} // namespace rawstor
