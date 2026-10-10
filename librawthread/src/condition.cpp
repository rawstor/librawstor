#include "rawthread/condition.hpp"

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
            wake = std::make_shared<Wake>();
            _waiters.push_back(wake);
        }
        co_await wake->wait(queue);
    }
}

void Condition::notify_all() noexcept {
    for (const std::shared_ptr<Wake>& wake : _waiters) {
        wake->signal();
    }
    _waiters.clear();
}

} // namespace rawthread
