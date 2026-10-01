#ifndef RAWSTOR_DEADLINE_HPP
#define RAWSTOR_DEADLINE_HPP

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <algorithm>
#include <system_error>

#include <cerrno>
#include <climits>
#include <cstdint>

namespace rawstor {

// Runs `action` once `milliseconds` elapse, unless the timer is cancelled
// through `event` first. Cancelling the timer is drained before its frame
// or captured action goes away. Long millisecond values are split to fit
// Queue::timeout().
template <typename Action>
rawstd::Task<void> deadline(
    rawio::Queue& queue, unsigned int milliseconds, rawio::Event*& event,
    bool& expired, Action& action
) {
    uint64_t remaining = static_cast<uint64_t>(milliseconds) * 1000;
    while (remaining != 0) {
        unsigned int part =
            static_cast<unsigned int>(std::min<uint64_t>(remaining, UINT_MAX));
        auto timer = queue.timeout(part);
        event = timer.event();
        try {
            co_await timer;
        } catch (const std::system_error& e) {
            event = nullptr;
            if (e.code().value() == ECANCELED) {
                co_return;
            }
            throw;
        }
        event = nullptr;
        remaining -= part;
    }
    expired = true;
    co_await action();
}

} // namespace rawstor

#endif // RAWSTOR_DEADLINE_HPP
