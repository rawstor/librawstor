#include "rawthread/condition.hpp"

#include <utility>

namespace rawthread {

rawstd::Task<void> Condition::wait(
    rawio::Queue& queue, std::mutex& mu, std::function<bool()> ready
) {
    for (;;) {
        std::shared_ptr<Wake> wake;
        {
            std::lock_guard<std::mutex> guard(mu);
            if (ready()) {
                co_return;
            }
            if (!_wake) {
                _wake = std::make_shared<Wake>();
            }
            wake = _wake;
        }
        co_await wake->wait(queue);
    }
}

void Condition::notify_all() noexcept {
    // Waiters own this generation until their polls complete. A waiter
    // that rechecks a false predicate joins a fresh, unsignalled generation.
    std::shared_ptr<Wake> wake = std::move(_wake);
    if (wake) {
        wake->signal();
    }
}

} // namespace rawthread
