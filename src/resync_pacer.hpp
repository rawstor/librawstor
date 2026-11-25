#ifndef RAWSTOR_RESYNC_PACER_HPP
#define RAWSTOR_RESYNC_PACER_HPP

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace rawstor {

/**
 * Paces the copy of resyncs and heals to a byte rate shared by every sweeper
 * of the process, whichever thread and queue it runs on.
 *
 * It keeps one deadline: when the copy it paces last allowed ends. A sweeper
 * that copied `size` bytes starting at `start_ns` reserves the next stretch of
 * `size / rate` from the later of that deadline and `start_ns` (an idle time
 * is not saved up, so there is no burst after it), and waits on its own queue
 * until the end of the stretch. The copy itself counts toward the stretch: a
 * region that took longer than that to copy is not waited for at all.
 * Nothing blocks.
 */
class ResyncPacer final {
private:
    std::atomic<uint64_t> _deadline;

public:
    ResyncPacer() : _deadline(0) {}

    ResyncPacer(const ResyncPacer&) = delete;
    ResyncPacer(ResyncPacer&&) = delete;
    ResyncPacer& operator=(const ResyncPacer&) = delete;
    ResyncPacer& operator=(ResyncPacer&&) = delete;

    /**
     * Reserves the time `size` bytes take at `rate` bytes per second for a
     * copy that began at `start_ns`, and returns the time, in the same clock,
     * to wait until before the next one. Zero `rate` is no limit and returns
     * `start_ns`.
     */
    uint64_t reserve(uint64_t start_ns, size_t size, unsigned int rate) {
        if (rate == 0 || size == 0) {
            return start_ns;
        }
        const uint64_t cost =
            static_cast<uint64_t>(size) * 1000000000ull / rate;
        uint64_t deadline = _deadline.load(std::memory_order_relaxed);
        uint64_t next;
        do {
            next = std::max(start_ns, deadline) + cost;
        } while (!_deadline.compare_exchange_weak(
            deadline, next, std::memory_order_relaxed
        ));
        return next;
    }
};

} // namespace rawstor

#endif // RAWSTOR_RESYNC_PACER_HPP
