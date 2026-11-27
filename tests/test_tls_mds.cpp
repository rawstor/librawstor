#include "object_env.hpp"
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

const std::string mds_1 = "018f4e2a-0000-7000-8000-0000000000e1";
const std::string mds_2 = "018f4e2a-0000-7000-8000-0000000000e2";

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
                rawstor::mdsserver::ObjectStore store(
                    db, rawstor::tests::test_mds_opts()
                );
                rawstor::tests::enter_topology(
                    store, topology, RawstorLocationInfo{123, 456}
                );
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

TEST(TlsMdsTest, an_mds_certificate_has_no_mds_admin_permissions) {
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain + "/mds/" + mds_1
    );
    MdsServer server(8906);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), -EACCES);
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

TEST(TlsMdsTest, the_configured_mds_name_is_required) {
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain + "/mds/" +
            mds_1,
        mds_2
    );
    MdsServer server(8909);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_NE(location_info(*queue, server.location(), &info), 0);
}

TEST(TlsMdsTest, the_configured_mds_name_is_accepted) {
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain + "/mds/" +
            mds_1,
        mds_1
    );
    MdsServer server(8910);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_EQ(location_info(*queue, server.location(), &info), -EACCES);
}

// The same MDS certificate is used by the test client: a successful TLS
// handshake still ends in EACCES for LOCATION_INFO on the MDS.
// An MDS hosts a witness on its own port, and the topology lists it as an
// ost:// location. The server at that address is the MDS, with the identity of
// an MDS, whatever id the witness has.
TEST(TlsMdsTest, the_witness_an_mds_hosts_is_accepted_at_its_address) {
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain + "/mds/" + mds_1
    );
    MdsServer server(8911);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    // Not known as an MDS yet, an ost:// address is expected to be an OST.
    EXPECT_NE(location_info(*queue, "ost://127.0.0.1:8911", &info), 0);

    ASSERT_EQ(location_info(*queue, server.location(), &info), -EACCES);
    EXPECT_EQ(location_info(*queue, "ost://127.0.0.1:8911", &info), -EACCES);
}

TEST(TlsMdsTest, the_witness_an_mds_hosts_needs_the_configured_mds_name) {
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain + "/mds/" +
            mds_1,
        mds_2
    );
    MdsServer server(8912);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_NE(location_info(*queue, server.location(), &info), 0);
    EXPECT_NE(location_info(*queue, "ost://127.0.0.1:8912", &info), 0);
}

// An address that was tried as an MDS and refused is not one: an ost://
// connection to it is still expected to be an OST.
TEST(TlsMdsTest, an_address_refused_as_an_mds_stays_an_ost_address) {
    // The server presents an OST's certificate, so it is no MDS.
    rawstor::tests::TlsProcess tls(
        "spiffe://" + rawstor::tests::TlsProcess::trust_domain +
        "/ost/018f4e2a-0000-7000-8000-0000000000aa"
    );
    MdsServer server(8913);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    EXPECT_NE(location_info(*queue, server.location(), &info), 0);
    // It was refused as an MDS, so as an OST address it takes an OST.
    EXPECT_EQ(location_info(*queue, "ost://127.0.0.1:8913", &info), -EACCES);
}
