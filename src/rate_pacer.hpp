#ifndef RAWSTOR_RATE_PACER_HPP
#define RAWSTOR_RATE_PACER_HPP

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace rawstor {

/**
 * Paces a copy to a byte rate. Everything that copies under one pacer shares
 * its rate, whichever thread and queue it runs on; each kind of copy (the
 * resync of a mirror, an export) has a pacer of its own.
 *
 * A copier calls acquire() with the size of the block it is about to move and
 * moves it when the call returns. A call that fits the rate returns at once;
 * one that does not waits, on the caller's own queue, for the time the blocks
 * before it still owe. The time the copy itself takes counts, so a copier
 * whose blocks are slow to move is not waited for at all. An idle time is not
 * saved up: there is no burst after it.
 */
class RatePacer final {
private:
    const unsigned int _rate;
    // When the blocks acquired so far are paid for, on _now_ns()'s clock.
    std::atomic<uint64_t> _deadline;

    static uint64_t _now_ns() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            )
                .count()
        );
    }

    // Takes the stretch `bytes` need and returns when it begins.
    uint64_t _reserve(size_t bytes) {
        const uint64_t cost =
            static_cast<uint64_t>(bytes) * 1000000000ull / _rate;
        const uint64_t now = _now_ns();
        uint64_t deadline = _deadline.load(std::memory_order_relaxed);
        uint64_t start;
        do {
            start = std::max(now, deadline);
        } while (!_deadline.compare_exchange_weak(
            deadline, start + cost, std::memory_order_relaxed
        ));
        return start;
    }

public:
    /**
     * @param rate  Bytes per second; zero is no limit.
     */
    explicit RatePacer(unsigned int rate) : _rate(rate), _deadline(0) {}

    RatePacer(const RatePacer&) = delete;
    RatePacer(RatePacer&&) = delete;
    RatePacer& operator=(const RatePacer&) = delete;
    RatePacer& operator=(RatePacer&&) = delete;

    /**
     * Takes the time `bytes` need at the rate and returns when the caller may
     * move them. The wait is on `queue` and can be cancelled with
     * Task::cancel(): it throws then, as Queue::timeout() does, and the
     * caller is not to copy.
     */
    rawstd::Task<void> acquire(rawio::Queue& queue, size_t bytes) {
        if (_rate == 0 || bytes == 0) {
            co_return;
        }
        const uint64_t start = _reserve(bytes);
        for (;;) {
            const uint64_t now = _now_ns();
            if (now >= start) {
                co_return;
            }
            const uint64_t usec = std::clamp<uint64_t>(
                (start - now) / 1000, 1, std::numeric_limits<unsigned>::max()
            );
            co_await queue.timeout(static_cast<unsigned int>(usec));
        }
    }
};

} // namespace rawstor

#endif // RAWSTOR_RATE_PACER_HPP
