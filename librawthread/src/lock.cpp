#include "rawthread/lock.hpp"

namespace rawthread {

rawstd::Task<void> Lock::lock(rawio::Queue& queue) {
    co_await _released.wait(queue, _mu, [this]() {
        if (_busy) {
            return false;
        }
        _busy = true;
        return true;
    });
}

void Lock::unlock() noexcept {
    std::lock_guard<std::mutex> guard(_mu);
    _busy = false;
    _released.notify_all();
}

} // namespace rawthread
