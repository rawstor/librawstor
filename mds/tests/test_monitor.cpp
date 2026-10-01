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

TEST(MonitorTest, phases_spread_over_interval) {
    constexpr unsigned interval = 300000;
    constexpr unsigned buckets = 10;
    constexpr unsigned osts = 5000;
    unsigned counts[buckets] = {};
    for (unsigned i = 1; i <= osts; ++i) {
        auto ost = ost_at("ost://10.0.0.1:8080", i);
        auto phase = Monitor::phase(ost, interval);
        EXPECT_EQ(phase, Monitor::phase(ost, interval));
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(phase)
                      .count();
        ASSERT_GE(ms, 0);
        ASSERT_LT(ms, interval);
        ++counts[ms * buckets / interval];
    }
    for (unsigned count : counts) {
        EXPECT_GT(count, osts / buckets * 8 / 10);
        EXPECT_LT(count, osts / buckets * 12 / 10);
    }
}

TEST(MonitorTest, next_due_keeps_phase_and_interval) {
    using namespace std::chrono_literals;
    Monitor::Clock::time_point epoch{};
    Monitor::Clock::duration interval = 300s;
    Monitor::Clock::duration phase = 70s;

    // A probe finishing shortly after its slot runs again one interval
    // after that slot.
    EXPECT_EQ(
        Monitor::next_due(epoch, phase, interval, epoch + phase + 2s),
        epoch + phase + interval
    );
    EXPECT_EQ(
        Monitor::next_due(epoch, phase, interval, epoch + 1000s),
        epoch + phase + 4 * interval
    );
    // The first probe runs at startup; the next one waits at least half an
    // interval, then joins its phase.
    EXPECT_EQ(
        Monitor::next_due(epoch, phase, interval, epoch + 1s),
        epoch + phase + interval
    );
    EXPECT_EQ(
        Monitor::next_due(epoch, 200s, interval, epoch + 1s), epoch + 200s
    );
    // A probe slower than half an interval skips to the following slot.
    EXPECT_EQ(
        Monitor::next_due(epoch, phase, interval, epoch + phase + 200s),
        epoch + phase + 2 * interval
    );
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
