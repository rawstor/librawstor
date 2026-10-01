#include <mds/monitor.hpp>

#include "location.hpp"

#include <rawio/awaitable.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>

#include <algorithm>
#include <exception>
#include <utility>

#include <cerrno>

namespace rawstor {
namespace mdsserver {

Monitor::Monitor(ObjectStore& store, Opts opts, int wake_fd) :
    _store(store),
    _opts(opts),
    _wake_fd(wake_fd) {
    if (opts.info_interval == 0 || opts.info_concurrency == 0 ||
        opts.info_concurrency > 4096 || wake_fd < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    unsigned int depth = 16;
    while (depth < opts.info_concurrency * 8 + 8) {
        depth *= 2;
    }
    _queue = rawio::Queue::create(depth);
    _active.reserve(opts.info_concurrency);
    _store.reset_backend_availability();
}

std::string Monitor::_key(const TopologyOST& ost) {
    return std::string(
               reinterpret_cast<const char*>(ost.id.bytes), sizeof(ost.id.bytes)
           ) +
           ost.location;
}

rawstd::Task<void> Monitor::_probe(TopologyOST ost) {
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

rawstd::Task<void> Monitor::_wake() {
    char byte;
    auto read = _queue->read(_wake_fd, &byte, 1);
    _wake_event = read.event();
    try {
        co_await read;
    } catch (const std::system_error& e) {
        if (e.code().value() != ECANCELED) {
            throw;
        }
    }
    _wake_event = nullptr;
    _stop = true;
}

void Monitor::_reload() {
    auto topology = _store.topology();
    if (topology == _topology) {
        return;
    }
    _topology = std::move(topology);
    _pending = {};
    _current.clear();
    for (const auto& ost : _topology->osts()) {
        auto key = _key(ost);
        _current.insert(key);
        if (!_inflight.contains(key)) {
            _pending.push(Pending{ost, _due[key]});
        }
    }
    std::erase_if(_due, [this](const auto& entry) {
        return !_current.contains(entry.first);
    });
}

void Monitor::_wait(unsigned int milliseconds) {
    try {
        _queue->wait_timeout(milliseconds);
    } catch (const std::system_error& e) {
        if (e.code().value() != ETIME && e.code().value() != EINTR) {
            throw;
        }
    }
}

void Monitor::loop() {
    _wake_task = _wake();
    std::exception_ptr error;
    while (true) {
        _reload();
        for (size_t i = 0; i < _active.size();) {
            auto& active = _active[i];
            if (!active.task.done()) {
                ++i;
                continue;
            }
            try {
                active.task.get();
            } catch (...) {
                if (!error) {
                    error = std::current_exception();
                }
                _stop = true;
                if (_wake_event) {
                    _queue->cancel(_wake_event);
                }
            }
            auto key = _key(active.ost);
            _inflight.erase(key);
            if (_current.contains(key)) {
                auto due = Clock::now() +
                           std::chrono::milliseconds(_opts.info_interval);
                _due[key] = due;
                _pending.push(Pending{active.ost, due});
            }
            _active.erase(_active.begin() + i);
        }
        if (_stop && _active.empty()) {
            while (!_wake_task.done()) {
                _wait(100);
            }
            _wake_task.get();
            if (error) {
                std::rethrow_exception(error);
            }
            break;
        }
        while (!_stop && _active.size() < _opts.info_concurrency &&
               !_pending.empty() && _pending.top().due <= Clock::now()) {
            auto ost = _pending.top().ost;
            _pending.pop();
            _inflight.insert(_key(ost));
            auto task = _probe(ost);
            _active.push_back(Active{std::move(ost), std::move(task)});
        }
        bool completed =
            std::any_of(_active.begin(), _active.end(), [](const auto& active) {
                return active.task.done();
            });
        unsigned int wait_ms = completed ? 0 : 100;
        if (!_stop && _active.size() < _opts.info_concurrency &&
            !_pending.empty()) {
            auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                            _pending.top().due - Clock::now()
            )
                            .count();
            wait_ms = static_cast<unsigned int>(
                std::clamp<int64_t>(left, 0, wait_ms)
            );
        }
        _wait(wait_ms);
    }
}

} // namespace mdsserver
} // namespace rawstor
