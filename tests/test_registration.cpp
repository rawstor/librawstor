// An OST keeps itself in the topology of the MDS of its cluster (docs/mds.md,
// "OST registration"): a real ostserver::Registrar serving a file:// store,
// against a real mdsserver::Server.
#include "rawio_sync.hpp"
#include "tmp_dir.hpp"

#include <mds/server.hpp>
#include <mds/store.hpp>

#include <ost/registrar.hpp>

#include <rawio/queue.hpp>

#include <rawstd/pipe.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <unistd.h>

namespace {

using rawstor::mdsserver::ObjectStore;
using rawstor::mdsserver::TopologyOST;
using rawstor::ostserver::Registrar;

const char* const ost_id = "018f4e2a-0000-7000-8000-0000000000a1";

// A real rawstor-mds on its own thread. Its store is the test's to look at.
class Mds {
private:
    rawstor::tests::TmpDir _dir;
    std::unique_ptr<ObjectStore> _store;
    int _listen_fd;
    int _wake_write_fd = -1;
    std::thread _thread;
    unsigned int _port;

public:
    Mds(unsigned int port, const rawstor::mdsserver::Opts& opts) :
        _store(
            std::make_unique<ObjectStore>(
                (_dir.path() / "mds.db").string(), opts
            )
        ),
        _listen_fd(rawstor::mdsserver::Server::bind_listen("127.0.0.1", port)),
        _port(port) {
        rawstd::Pipe wake(rawstd::Pipe::Mode::NonBlocking);
        _wake_write_fd = wake.release_write();
        _thread = std::thread([this, wake_fd = wake.release_read()]() {
            rawstor::mdsserver::Server s(64, _listen_fd, *_store, wake_fd);
            s.loop();
            close(wake_fd);
        });
    }

    Mds(const Mds&) = delete;
    Mds& operator=(const Mds&) = delete;

    ~Mds() {
        char byte = 0;
        ssize_t ignored = write(_wake_write_fd, &byte, 1);
        (void)ignored;
        _thread.join();
        close(_wake_write_fd);
        close(_listen_fd);
    }

    ObjectStore& store() { return *_store; }

    std::string location() const {
        return "mds://127.0.0.1:" + std::to_string(_port);
    }
};

// A Registrar on its own thread, stopped and joined when it goes.
class Ost {
private:
    Registrar _registrar;
    std::thread _thread;

public:
    Ost(Registrar::Config config, const std::string& store) :
        _registrar(std::move(config), rawstd::URI(store), nullptr),
        _thread([this]() { _registrar.loop(); }) {}

    Ost(const Ost&) = delete;
    Ost& operator=(const Ost&) = delete;

    ~Ost() { stop(); }

    Registrar& registrar() { return _registrar; }

    void stop() {
        if (_thread.joinable()) {
            _registrar.stop();
            _thread.join();
        }
    }
};

rawstor::mdsserver::Opts fast_opts() {
    rawstor::mdsserver::Opts opts;
    opts.heartbeat_interval = 100;
    opts.info_refresh_delay = 0;
    return opts;
}

Registrar::Config config_of(const Mds& mds) {
    Registrar::Config config;
    EXPECT_EQ(rawstd_uuid_from_string(&config.id, ost_id), 0);
    config.mds = mds.location();
    config.location = "ost://127.0.0.1:1";
    config.weight = 7;
    config.domain = "dc1/rack1/host1";
    return config;
}

// Waits, up to a generous limit, for what a background thread is to bring
// about.
bool eventually(const std::function<bool()>& condition) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (!condition()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

RawstdUUID id_of(const char* text) {
    RawstdUUID id{};
    EXPECT_EQ(rawstd_uuid_from_string(&id, text), 0);
    return id;
}

} // namespace

TEST(RegistrationTest, an_ost_registers_itself_and_leaves) {
    Mds mds(8950, fast_opts());
    rawstor::tests::TmpDir store;
    RawstdUUID id = id_of(ost_id);
    {
        Ost ost(config_of(mds), store.uri());
        ASSERT_TRUE(eventually([&] {
            return mds.store().backend_available(id);
        }));
        auto topology = mds.store().topology();
        ASSERT_EQ(topology->osts().size(), 1u);
        const TopologyOST& entry = topology->osts()[0];
        EXPECT_EQ(rawstd_uuid_cmp(&entry.id, &id), 0);
        EXPECT_EQ(entry.location, "ost://127.0.0.1:1");
        EXPECT_EQ(entry.weight, 7u);
        EXPECT_EQ(entry.path[0], "");
        EXPECT_EQ(entry.path[1], "dc1");
        EXPECT_EQ(entry.path[2], "rack1");
        EXPECT_EQ(entry.path[3], "host1");
        EXPECT_TRUE(entry.supports(rawstor::mdsserver::Role::Data));
        EXPECT_TRUE(entry.supports(rawstor::mdsserver::Role::Witness));
    }
    // Stopped: it said it leaves, and with nothing on it it is gone.
    EXPECT_FALSE(mds.store().backend_available(id));
    EXPECT_TRUE(mds.store().topology()->osts().empty());
}

// The store is sampled again once a member is created on it: the MDS sees
// the space it takes well before the next regular sample.
TEST(RegistrationTest, a_change_of_members_is_sampled) {
    Mds mds(8951, fast_opts());
    rawstor::tests::TmpDir store;
    Ost ost(config_of(mds), store.uri());
    ASSERT_TRUE(eventually([&] {
        return mds.store().backend_available(id_of(ost_id));
    }));
    uint64_t before = mds.store().info().used;

    auto queue = rawio::Queue::create(64);
    std::string target =
        rawstd::URI(
            rawstd::URI(store.uri()), "018f4e2a-3000-7000-8000-0000000000a1"
        )
            .str();
    RawstorObjectSpec spec{};
    spec.size = 1u << 20;
    spec.width = 1;
    spec.chunk_size = spec.size;
    ASSERT_EQ(
        rawstor::tests::sync_run(
            queue.get(),
            [&](auto cb, void* data) {
                return rawstor_target_create(
                    queue.get(), target.c_str(), &spec, cb, data
                );
            }
        ),
        0
    );
    ost.registrar().members_changed();

    EXPECT_TRUE(eventually([&] { return mds.store().info().used > before; }));
}
