#include <mds/monitor.hpp>

#include "location.hpp"

#include <rawio/awaitable.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.hpp>

#include <algorithm>
#include <exception>
#include <system_error>
#include <unordered_set>
#include <utility>

#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstring>

namespace rawstor {
namespace mdsserver {

Monitor::Monitor(ObjectStore& store, Opts opts) :
    _store(store),
    _opts(opts),
    _wake(rawstd::Pipe::Mode::NonBlocking),
    _epoch(Clock::now()),
    _slots(opts.info_concurrency) {
    if (opts.info_interval == 0 || opts.info_concurrency == 0 ||
        opts.info_concurrency > Opts::max_info_concurrency) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    // Sized for the in-flight probes; sleeping probe loops only hold
    // timers, which io_uring and the poll backend keep outside this depth.
    unsigned int depth = 16;
    while (depth < opts.info_concurrency * 8 + 8) {
        depth *= 2;
    }
    _queue = rawio::Queue::create(depth);
    _store.reset_backend_availability();
}

std::string Monitor::_key(const TopologyOST& ost) {
    return std::string(
               reinterpret_cast<const char*>(ost.id.bytes), sizeof(ost.id.bytes)
           ) +
           ost.location;
}

Monitor::Clock::duration
Monitor::phase(const TopologyOST& ost, unsigned int interval) {
    auto key = _key(ost);
    uint64_t hash = rawstd_hash_stable(key.data(), key.size());
    return std::chrono::duration_cast<Clock::duration>(
        std::chrono::milliseconds(hash % interval)
    );
}

Monitor::Clock::time_point Monitor::next_due(
    Clock::time_point epoch, Clock::duration phase, Clock::duration interval,
    Clock::time_point completed
) {
    auto first = epoch + phase;
    auto earliest = completed + interval / 2;
    if (earliest <= first) {
        return first;
    }
    auto periods =
        (earliest - first + interval - Clock::duration(1)) / interval;
    return first + periods * interval;
}

rawstd::Task<void> Monitor::_probe(const TopologyOST& ost) {
    RawstorLocationInfo info{};
    bool available = false;
    try {
        Location location(std::vector<rawstd::URI>{rawstd::URI(ost.location)});
        info = co_await location.info(*_queue);
        available = true;
    } catch (const std::exception& e) {
        rawstd_warning(
            "MDS info probe for %s failed: %s\n", ost.location.c_str(), e.what()
        );
    }
    _store.update_backend(ost, available ? &info : nullptr);
}

void Monitor::_notify(char command) {
    ssize_t ignored = write(_wake.write_fd(), &command, 1);
    (void)ignored;
}

void Monitor::_fail(std::exception_ptr error) {
    if (!_error) {
        _error = error;
    }
    _stop = true;
    if (_wake_event != nullptr) {
        _queue->cancel(_wake_event);
    }
}

rawstd::Task<void> Monitor::_sleep_until(Watch& watch, Clock::time_point due) {
    while (watch.alive) {
        auto now = Clock::now();
        if (due <= now) {
            co_return;
        }
        auto usec =
            std::chrono::ceil<std::chrono::microseconds>(due - now).count();
        auto timer = _queue->timeout(
            static_cast<unsigned int>(std::min<int64_t>(usec, UINT_MAX))
        );
        watch.timer = timer.event();
        try {
            co_await timer;
        } catch (const std::system_error& e) {
            watch.timer = nullptr;
            if (e.code().value() == ECANCELED) {
                co_return;
            }
            throw;
        }
        watch.timer = nullptr;
    }
}

rawstd::Task<void> Monitor::_watch(Watch& watch) {
    // The first probe runs at once: the OST is unavailable for placement
    // until it succeeds.
    try {
        while (true) {
            co_await _slots.acquire();
            if (!watch.alive) {
                _slots.release();
                break;
            }
            std::exception_ptr error;
            try {
                co_await _probe(watch.ost);
            } catch (...) {
                error = std::current_exception();
            }
            _slots.release();
            if (error) {
                std::rethrow_exception(error);
            }
            if (!watch.alive) {
                break;
            }
            co_await _sleep_until(
                watch,
                next_due(
                    _epoch, phase(watch.ost, _opts.info_interval),
                    std::chrono::milliseconds(_opts.info_interval), Clock::now()
                )
            );
            if (!watch.alive) {
                break;
            }
        }
    } catch (...) {
        _fail(std::current_exception());
    }
}

rawstd::Task<void> Monitor::_wake_up(std::vector<Watch*> watches) {
    // One cancellation at a time: cancelling thousands of sleeping loops
    // at once would overflow the completion ring with the cancellations
    // and the timers they complete.
    for (Watch* watch : watches) {
        if (watch->timer != nullptr) {
            co_await _queue->cancel(watch->timer);
        }
    }
}

rawstd::Task<void> Monitor::_retire(std::vector<Watch*> watches) {
    for (Watch* watch : watches) {
        watch->alive = false;
    }
    co_await _wake_up(std::move(watches));
}

rawstd::Task<void> Monitor::_reload() {
    auto topology = _store.topology();
    if (_stop || topology == _topology) {
        co_return;
    }
    _topology = std::move(topology);
    std::unordered_set<std::string> current;
    // A kept OST the store no longer counts as available (it failed, or
    // was dropped and re-added between two reloads) is probed now rather
    // than at its next slot.
    std::vector<Watch*> unavailable;
    for (const auto& ost : _topology->osts()) {
        auto key = _key(ost);
        current.insert(key);
        auto found = _watches.find(key);
        if (found != _watches.end()) {
            if (!_store.backend_available(ost.id)) {
                unavailable.push_back(found->second.get());
            }
            continue;
        }
        auto watch = std::make_unique<Watch>();
        watch->ost = ost;
        Watch& started = *watch;
        _watches.emplace(std::move(key), std::move(watch));
        started.task = _watch(started);
    }
    std::vector<Watch*> removed;
    for (auto it = _watches.begin(); it != _watches.end();) {
        if (current.contains(it->first)) {
            ++it;
            continue;
        }
        removed.push_back(it->second.get());
        _retired.push_back(std::move(it->second));
        it = _watches.erase(it);
    }
    co_await _retire(std::move(removed));
    co_await _wake_up(std::move(unavailable));
    std::erase_if(_retired, [](const auto& watch) {
        return watch->task.done();
    });
}

rawstd::Task<void> Monitor::_control() {
    co_await _reload();
    char commands[64];
    while (!_stop) {
        auto read = _queue->read(_wake.read_fd(), commands, sizeof(commands));
        _wake_event = read.event();
        size_t n = 0;
        try {
            n = co_await read;
        } catch (const std::system_error& e) {
            _wake_event = nullptr;
            if (e.code().value() != ECANCELED) {
                _fail(std::current_exception());
            }
            break;
        }
        _wake_event = nullptr;
        if (n == 0 || memchr(commands, 's', n) != nullptr) {
            break;
        }
        co_await _reload();
    }

    _stop = true;
    std::vector<Watch*> all;
    for (auto& [key, watch] : _watches) {
        all.push_back(watch.get());
        _retired.push_back(std::move(watch));
    }
    _watches.clear();
    co_await _retire(std::move(all));
    for (auto& watch : _retired) {
        // Awaiting `watch->task` directly crashes GCC 13 (internal
        // compiler error); a named reference compiles everywhere.
        rawstd::Task<void>& task = watch->task;
        co_await task;
    }
    _retired.clear();
}

void Monitor::loop() {
    rawstd::Task<void> control = _control();
    while (!control.done()) {
        try {
            _queue->wait();
        } catch (const std::system_error& e) {
            if (e.code().value() != EINTR) {
                throw;
            }
        }
    }
    control.get();
    if (_error) {
        std::rethrow_exception(_error);
    }
}

void Monitor::reload() {
    _notify('r');
}

void Monitor::stop() {
    _notify('s');
}

} // namespace mdsserver
} // namespace rawstor
