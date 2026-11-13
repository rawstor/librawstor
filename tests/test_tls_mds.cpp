#include "rawio_sync.hpp"
#include "tls_process.hpp"
#include "tmp_dir.hpp"

#include <mds/server.hpp>
#include <mds/topology.hpp>

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/pipe.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>

#include <gtest/gtest.h>

#include <exception>
#include <future>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// A real rawstor-mds on its own thread, with one OST in its topology.
class MdsServer {
private:
    rawstor::tests::TmpDir _dir;
    int _listen_fd;
    int _wake_write_fd;
    std::thread _thread;
    unsigned int _port;

public:
    explicit MdsServer(unsigned int port) :
        _listen_fd(rawstor::mdsserver::Server::bind_listen("127.0.0.1", port)),
        _wake_write_fd(-1),
        _port(port) {
        RawstdUUID ost_id;
        int res = rawstd_uuid_from_string(
            &ost_id, "018f4e2a-0000-7000-8000-000000000001"
        );
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        rawstor::mdsserver::Topology topology;
        rawstor::mdsserver::TopologyOST ost{};
        ost.id = ost_id;
        ost.location = "ost://127.0.0.1:1";
        ost.weight = 100;
        ost.path[0] = "dc1";
        ost.path[1] = "row1";
        ost.path[2] = "rack1";
        ost.path[3] = "host1";
        topology.add(ost);

        rawstd::Pipe wake(rawstd::Pipe::Mode::NonBlocking);
        _wake_write_fd = wake.release_write();
        int wake_read_fd = wake.release_read();

        auto ready = std::make_shared<std::promise<void>>();
        std::future<void> ready_future = ready->get_future();
        std::string db = (_dir.path() / "mds.db").string();
        _thread = std::thread([fd = _listen_fd, db, topology, wake_read_fd,
                               ready]() mutable {
            try {
                rawstor::mdsserver::ObjectStore store(db, std::move(topology));
                RawstorLocationInfo info{123, 456};
                for (const auto& ost : store.topology()->osts()) {
                    store.update_backend(ost, &info);
                }
                rawstor::mdsserver::Server s(64, fd, store, wake_read_fd);
                ready->set_value();
                s.loop();
            } catch (...) {
                std::exception_ptr e = std::current_exception();
                try {
                    ready->set_exception(e);
                } catch (const std::future_error&) {
                }
            }
        });
        ready_future.get();
    }

    MdsServer(const MdsServer&) = delete;
    MdsServer& operator=(const MdsServer&) = delete;

    ~MdsServer() {
        char byte = 0;
        ssize_t ignored = write(_wake_write_fd, &byte, 1);
        (void)ignored;
        _thread.join();
        close(_wake_write_fd);
        close(_listen_fd);
    }

    std::string location() const {
        std::ostringstream oss;
        oss << "mds://127.0.0.1:" << _port;
        return oss.str();
    }
};

ssize_t location_info(
    rawio::Queue& queue, const std::string& location, RawstorLocationInfo* info
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_info(&queue, location.c_str(), info, cb, data);
    });
}

} // namespace

TEST(TlsMdsTest, location_info_over_tls) {
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain + "/mds/mds-1"
    );
    MdsServer server(8906);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), 0);
    EXPECT_EQ(info.used, (uint64_t)123);
    EXPECT_EQ(info.total, (uint64_t)456);
}

TEST(TlsMdsTest, an_ost_identity_is_not_accepted_for_an_mds) {
    // The process presents an OST's certificate everywhere, so a client
    // connecting to an mds:// address finds a server of the wrong role.
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain +
        "/ost/018f4e2a-0000-7000-8000-0000000000aa"
    );
    MdsServer server(8907);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_NE(location_info(*queue, server.location(), &info), 0);
}
