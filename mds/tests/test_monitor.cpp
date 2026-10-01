#include <mds/monitor.hpp>

#include "tmp_dir.hpp"

#include <rawstd/pipe.hpp>
#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <chrono>
#include <exception>
#include <filesystem>
#include <thread>

#include <unistd.h>

namespace {

using namespace rawstor::mdsserver;

TopologyOST ost_at(const std::string& location, unsigned index = 1) {
    TopologyOST ost{};
    rawstd_uuid_from_string(&ost.id, "00000000-0000-7000-8000-000000000000");
    ost.id.bytes[14] = static_cast<uint8_t>(index >> 8);
    ost.id.bytes[15] = static_cast<uint8_t>(index);
    ost.location = location;
    ost.weight = 100;
    ost.path[3] = "host";
    return ost;
}

class RunningMonitor {
private:
    rawstd::Pipe _wake{rawstd::Pipe::Mode::NonBlocking};
    Monitor _monitor;
    std::exception_ptr _error;
    std::thread _thread;

public:
    RunningMonitor(ObjectStore& store, Opts opts) :
        _monitor(store, opts, _wake.read_fd()),
        _thread([this]() {
            try {
                _monitor.loop();
            } catch (...) {
                _error = std::current_exception();
            }
        }) {}

    ~RunningMonitor() { stop(); }

    void stop() {
        if (_thread.joinable()) {
            char byte = 0;
            ssize_t ignored = write(_wake.write_fd(), &byte, 1);
            (void)ignored;
            _thread.join();
        }
    }

    void check() {
        stop();
        if (_error) {
            std::rethrow_exception(_error);
        }
    }
};

template <typename Predicate>
bool eventually(Predicate predicate, unsigned seconds = 5) {
    auto until =
        std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    do {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() < until);
    return false;
}

TEST(MonitorTest, follows_reload_failure_and_recovery) {
    tests::TmpDir dir;
    ObjectStore store(dir.db_path(), Topology{});
    RunningMonitor monitor(store, Opts{20, 2});
    auto ost = ost_at(
        "file://" + std::filesystem::path(dir.db_path()).parent_path().string()
    );
    Topology topology;
    topology.add(ost);
    store.set_topology(topology);
    ASSERT_TRUE(eventually([&]() { return store.backend_available(ost.id); }));
    EXPECT_GT(store.info().total, 0u);

    ost.location += "/recovered";
    Topology moved;
    moved.add(ost);
    store.set_topology(moved);
    EXPECT_FALSE(store.backend_available(ost.id));
    EXPECT_EQ(store.info().total, 0u);
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(store.backend_available(ost.id));
    std::filesystem::create_directory(
        std::filesystem::path(dir.db_path()).parent_path() / "recovered"
    );
    ASSERT_TRUE(eventually([&]() { return store.backend_available(ost.id); }));
    EXPECT_GT(store.info().total, 0u);

    store.set_topology(Topology{});
    EXPECT_EQ(store.info().total, 0u);
    monitor.check();
    EXPECT_EQ(store.info().total, 0u);
}

// The largest accepted concurrency must still fit the queue it sizes.
TEST(MonitorTest, starts_with_max_concurrency) {
    tests::TmpDir dir;
    ObjectStore store(dir.db_path(), Topology{});
    RunningMonitor monitor(store, Opts{60000, Opts::max_info_concurrency});
    monitor.check();
}

TEST(MonitorTest, collects_five_thousand_backends_with_bounded_queue) {
    tests::TmpDir dir;
    Topology topology;
    for (unsigned i = 1; i <= 5000; ++i) {
        topology.add(ost_at(
            "file://" +
                std::filesystem::path(dir.db_path()).parent_path().string(),
            i
        ));
    }
    ObjectStore store(dir.db_path(), topology);
    RunningMonitor monitor(store, Opts{60000, 128});
    ASSERT_TRUE(eventually(
        [&]() {
            for (const auto& ost : topology.osts()) {
                if (!store.backend_available(ost.id)) {
                    return false;
                }
            }
            return true;
        },
        30
    ));
    EXPECT_GT(store.info().total, 0u);
    monitor.check();
}

} // namespace
