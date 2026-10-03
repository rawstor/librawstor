#ifndef RAWSTOR_MDS_MONITOR_HPP
#define RAWSTOR_MDS_MONITOR_HPP

#include "opts.hpp"
#include "store.hpp"

#include <rawio/queue.hpp>
#include <rawstd/coro.hpp>
#include <rawstd/pipe.hpp>

#include <atomic>
#include <chrono>
#include <exception>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawstor {
namespace mdsserver {

/* One collector for the whole MDS. Every OST in the topology has its own
 * probe loop: probe, then sleep until its next slot. A shared semaphore
 * bounds the in-flight Location::info() calls, each including Slot's
 * connect/I/O retries; loops waiting for a unit get it in FIFO order.
 * reload() and stop() may be called from any thread. Shutdown stops new
 * probes and drains the calls already in flight. */
class Monitor final {
public:
    using Clock = std::chrono::steady_clock;

private:
    struct Watch {
        TopologyOST ost;
        bool alive = true;
        rawio::Event* timer = nullptr;
        rawstd::Task<void> task;
    };

    ObjectStore& _store;
    Opts _opts;
    rawstd::Pipe _wake;
    Clock::time_point _epoch;
    std::unique_ptr<rawio::Queue> _queue;
    rawstd::Semaphore _slots;
    bool _stop = false;
    // Set by reload()/stop() from any thread; the pipe only wakes _control().
    std::atomic<bool> _reload_requested{false};
    std::atomic<bool> _stop_requested{false};
    std::exception_ptr _error;
    rawio::Event* _wake_event = nullptr;
    std::shared_ptr<const Topology> _topology;
    std::unordered_map<std::string, std::unique_ptr<Watch>> _watches;
    std::vector<std::unique_ptr<Watch>> _retired;

    static std::string _key(const TopologyOST& ost);
    void _wake_up_control();
    void _fail(std::exception_ptr error);
    rawstd::Task<void> _probe(const TopologyOST& ost);
    rawstd::Task<void> _sleep_until(Watch& watch, Clock::time_point due);
    rawstd::Task<void> _watch(Watch& watch);
    rawstd::Task<void> _wake_up(std::vector<Watch*> watches);
    rawstd::Task<void> _retire(std::vector<Watch*> watches);
    rawstd::Task<void> _reload();
    rawstd::Task<void> _control();

public:
    /* An OST's fixed offset within the polling interval, derived from its
     * id and location, so repeated probes of a large topology spread
     * evenly over the interval instead of following one burst. */
    static Clock::duration phase(const TopologyOST& ost, unsigned int interval);
    /* The first time at the OST's phase that is at least half an interval
     * after `completed`. Probes shorter than half an interval then keep
     * exactly one interval between starts. */
    static Clock::time_point next_due(
        Clock::time_point epoch, Clock::duration phase,
        Clock::duration interval, Clock::time_point completed
    );

    Monitor(ObjectStore& store, Opts opts);
    Monitor(const Monitor&) = delete;
    Monitor& operator=(const Monitor&) = delete;

    /* Runs until stop(), or rethrows the first probe-loop failure. */
    void loop();
    /* Re-reads the store's topology: starts loops for new OSTs, stops
     * those of removed OSTs and of OSTs whose location changed, and
     * probes kept OSTs that are unavailable without waiting for their
     * next slot. */
    void reload();
    void stop();
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_MONITOR_HPP
