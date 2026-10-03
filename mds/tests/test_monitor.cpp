#include <mds/monitor.hpp>

#include "tmp_dir.hpp"

#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <exception>
#include <filesystem>
#include <future>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
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
    Monitor _monitor;
    std::exception_ptr _error;
    std::thread _thread;

public:
    RunningMonitor(ObjectStore& store, Opts opts) :
        _monitor(store, opts),
        _thread([this]() {
            try {
                _monitor.loop();
            } catch (...) {
                _error = std::current_exception();
            }
        }) {}

    ~RunningMonitor() { stop(); }

    void reload() { _monitor.reload(); }

    void stop() {
        if (_thread.joinable()) {
            _monitor.stop();
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
    monitor.reload();
    ASSERT_TRUE(eventually([&]() { return store.backend_available(ost.id); }));
    EXPECT_GT(store.info().total, 0u);

    ost.location += "/recovered";
    Topology moved;
    moved.add(ost);
    store.set_topology(moved);
    monitor.reload();
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
    monitor.reload();
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

// Accepts connections and closes each one, unanswered, after `hold`;
// records how many were open at once.
class SilentServer {
private:
    int _fd;
    std::atomic<bool> _stop{false};
    std::atomic<unsigned> _max_open{0};
    std::thread _thread;

    void _run(std::chrono::milliseconds hold) {
        using Clock = std::chrono::steady_clock;
        std::deque<std::pair<int, Clock::time_point>> open;
        while (!_stop) {
            pollfd pfd{.fd = _fd, .events = POLLIN, .revents = 0};
            if (poll(&pfd, 1, 5) > 0) {
                int fd = ::accept(_fd, nullptr, nullptr);
                if (fd >= 0) {
                    open.emplace_back(fd, Clock::now());
                    _max_open = std::max<unsigned>(_max_open, open.size());
                }
            }
            while (!open.empty() &&
                   Clock::now() - open.front().second >= hold) {
                ::close(open.front().first);
                open.pop_front();
            }
        }
        for (auto& [fd, since] : open) {
            ::close(fd);
        }
    }

public:
    SilentServer(uint16_t port, std::chrono::milliseconds hold) {
        _fd = socket(AF_INET, SOCK_STREAM, 0);
        int on = 1;
        setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            listen(_fd, 64) != 0) {
            ::close(_fd);
            throw std::system_error(errno, std::generic_category());
        }
        _thread = std::thread([this, hold]() { _run(hold); });
    }

    ~SilentServer() {
        _stop = true;
        _thread.join();
        ::close(_fd);
    }

    unsigned max_open() const { return _max_open; }
};

TEST(MonitorTest, bounds_in_flight_probes) {
    SilentServer server(8810, std::chrono::milliseconds(300));
    tests::TmpDir dir;
    Topology topology;
    for (unsigned i = 1; i <= 10; ++i) {
        topology.add(ost_at("ost://127.0.0.1:8810", i));
    }
    ObjectStore store(dir.db_path(), topology);
    RunningMonitor monitor(store, Opts{60000, 3});
    ASSERT_TRUE(eventually([&]() { return server.max_open() == 3; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    EXPECT_EQ(server.max_open(), 3u);
    monitor.check();
}

// Probes waiting on peers that never answer are cut short by stop()
// instead of holding shutdown until they give up on their own.
TEST(MonitorTest, stop_cancels_probes_in_flight) {
    SilentServer server(8811, std::chrono::seconds(60));
    tests::TmpDir dir;
    Topology topology;
    for (unsigned i = 1; i <= 3; ++i) {
        topology.add(ost_at("ost://127.0.0.1:8811", i));
    }
    ObjectStore store(dir.db_path(), topology);
    RunningMonitor monitor(store, Opts{60000, 3});
    ASSERT_TRUE(eventually([&]() { return server.max_open() == 3; }));

    auto stopped =
        std::async(std::launch::async, [&monitor]() { monitor.check(); });
    if (stopped.wait_for(std::chrono::seconds(10)) !=
        std::future_status::ready) {
        ADD_FAILURE() << "stop() waited for the probes in flight";
        std::abort();
    }
    stopped.get();
    // Cancelled probes say nothing about the backends.
    for (const auto& ost : topology.osts()) {
        EXPECT_FALSE(store.backend_available(ost.id));
    }
}

// Reloads that fill the wake-up pipe before the loop drains it must not
// swallow a later stop().
TEST(MonitorTest, stop_survives_a_full_wake_up_pipe) {
    tests::TmpDir dir;
    ObjectStore store(dir.db_path(), Topology{});
    Monitor monitor(store, Opts{60000, 1});
    for (int i = 0; i < 100000; ++i) {
        monitor.reload();
    }
    monitor.stop();
    auto loop =
        std::async(std::launch::async, [&monitor]() { monitor.loop(); });
    if (loop.wait_for(std::chrono::seconds(10)) != std::future_status::ready) {
        ADD_FAILURE() << "loop() did not return after stop()";
        std::abort();
    }
    loop.get();
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

    // Every loop is asleep now: dropping them all cancels 5000 timers.
    store.set_topology(Topology{});
    monitor.reload();
    EXPECT_EQ(store.info().total, 0u);
    store.set_topology(topology);
    monitor.reload();
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
    monitor.check();
}

} // namespace
