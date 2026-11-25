#ifndef RAWSTOR_RATE_PACER_HPP
#define RAWSTOR_RATE_PACER_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace rawstor {

/**
 * Paces a copy to a byte rate shared by everything that uses the same pacer,
 * whichever thread and queue it runs on. Each kind of copy (the resync of a
 * mirror, an export) has a pacer of its own and a rate of its own.
 *
 * It keeps one deadline: when the copy it paces last allowed ends. A copier
 * that copied `size` bytes starting at `start_ns` reserves the next stretch of
 * `size / rate` from the later of that deadline and `start_ns` (an idle time
 * is not saved up, so there is no burst after it), and waits on its own queue
 * until the end of the stretch (wait_until()). The copy itself counts toward
 * the stretch: a block that took longer than that to copy is not waited for at
 * all. Nothing blocks.
 */
class RatePacer final {
private:
    std::atomic<uint64_t> _deadline;

public:
    RatePacer() : _deadline(0) {}

    RatePacer(const RatePacer&) = delete;
    RatePacer(RatePacer&&) = delete;
    RatePacer& operator=(const RatePacer&) = delete;
    RatePacer& operator=(RatePacer&&) = delete;

    /**
     * The clock reserve() and wait_until() count in, in nanoseconds.
     */
    static uint64_t now_ns() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            )
                .count()
        );
    }

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

/**
 * Waits on `queue` until `until_ns` (the clock of RatePacer::now_ns()), in
 * steps of at most `step`; `stop` is asked after each step, and when it says
 * yes the wait ends at once. Returns whether the time is up; false is a wait
 * `stop` cut short. A wait the queue cancels or fails throws, as
 * Queue::timeout() does.
 */
template <typename Stop>
rawstd::Task<bool> wait_until(
    rawio::Queue& queue, uint64_t until_ns, Stop stop,
    std::chrono::milliseconds step = std::chrono::milliseconds(100)
) {
    for (;;) {
        const uint64_t now_ns = RatePacer::now_ns();
        if (now_ns >= until_ns) {
            co_return true;
        }
        const auto left = std::min<std::chrono::nanoseconds>(
            std::chrono::nanoseconds(until_ns - now_ns), step
        );
        co_await queue.timeout(
            static_cast<unsigned int>(std::max<std::chrono::microseconds::rep>(
                1, std::chrono::duration_cast<std::chrono::microseconds>(left)
                       .count()
            ))
        );
        if (stop()) {
            co_return false;
        }
    }
}

} // namespace rawstor

#endif // RAWSTOR_RATE_PACER_HPP
