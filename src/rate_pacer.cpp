#include "rate_pacer.hpp"

#include <rawio/awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <limits>

namespace {

uint64_t now_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()
        )
            .count()
    );
}

} // namespace

namespace rawstor {

RatePacer::RatePacer(unsigned int rate) : _rate(rate), _deadline(0) {
}

uint64_t RatePacer::_reserve(size_t bytes) {
    const uint64_t cost = static_cast<uint64_t>(bytes) * 1000000000ull / _rate;
    const uint64_t now = now_ns();
    uint64_t deadline = _deadline.load(std::memory_order_relaxed);
    uint64_t start;
    do {
        start = std::max(now, deadline);
    } while (!_deadline.compare_exchange_weak(
        deadline, start + cost, std::memory_order_relaxed
    ));
    return start;
}

rawstd::Task<void> RatePacer::acquire(rawio::Queue& queue, size_t bytes) {
    if (_rate == 0 || bytes == 0) {
        co_return;
    }
    const uint64_t start = _reserve(bytes);
    for (;;) {
        const uint64_t now = now_ns();
        if (now >= start) {
            co_return;
        }
        const uint64_t usec = std::clamp<uint64_t>(
            (start - now) / 1000, 1, std::numeric_limits<unsigned>::max()
        );
        co_await queue.timeout(static_cast<unsigned int>(usec));
    }
}

} // namespace rawstor
