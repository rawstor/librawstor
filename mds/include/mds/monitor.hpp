#ifndef RAWSTOR_MDS_MONITOR_HPP
#define RAWSTOR_MDS_MONITOR_HPP

#include "opts.hpp"
#include "store.hpp"

#include <rawio/queue.hpp>
#include <rawstd/coro.hpp>

#include <chrono>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace rawstor {
namespace mdsserver {

/* One collector for the whole MDS, with a bounded number of in-flight
 * Location::info() calls. Every call includes Slot's connect/I/O retries.
 * Shutdown stops new probes and drains the calls already in flight. */
class Monitor final {
private:
    using Clock = std::chrono::steady_clock;
    struct Pending {
        TopologyOST ost;
        Clock::time_point due;
        bool operator<(const Pending& other) const { return due > other.due; }
    };
    struct Active {
        TopologyOST ost;
        rawstd::Task<void> task;
    };

    ObjectStore& _store;
    Opts _opts;
    int _wake_fd;
    bool _stop = false;
    std::unique_ptr<rawio::Queue> _queue;
    rawstd::Task<void> _wake_task;
    rawio::Event* _wake_event = nullptr;
    std::shared_ptr<const Topology> _topology;
    std::priority_queue<Pending> _pending;
    std::vector<Active> _active;
    std::unordered_set<std::string> _inflight;
    std::unordered_set<std::string> _current;
    std::unordered_map<std::string, Clock::time_point> _due;

    static std::string _key(const TopologyOST& ost);
    rawstd::Task<void> _probe(TopologyOST ost);
    rawstd::Task<void> _wake();
    void _reload();
    void _wait(unsigned int milliseconds);

public:
    Monitor(ObjectStore& store, Opts opts, int wake_fd);
    Monitor(const Monitor&) = delete;
    Monitor& operator=(const Monitor&) = delete;
    void loop();
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_MONITOR_HPP
