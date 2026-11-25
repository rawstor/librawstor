#ifndef RAWSTOR_RATE_PACER_HPP
#define RAWSTOR_RATE_PACER_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>

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
    // When the blocks acquired so far are paid for, on the steady clock.
    std::atomic<uint64_t> _deadline;

    // Takes the stretch `bytes` need and returns when it begins.
    uint64_t _reserve(size_t bytes);

public:
    /**
     * @param rate  Bytes per second; zero is no limit.
     */
    explicit RatePacer(unsigned int rate);

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
    rawstd::Task<void> acquire(rawio::Queue& queue, size_t bytes);
};

} // namespace rawstor

#endif // RAWSTOR_RATE_PACER_HPP
