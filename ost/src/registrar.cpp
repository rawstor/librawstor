#include <ost/registrar.hpp>

#include "meta_cache.hpp"
#include "opts.h"
#include "slot.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/logging.hpp>

#include <algorithm>
#include <exception>
#include <system_error>
#include <utility>
#include <vector>

#include <unistd.h>

#include <cerrno>
#include <climits>

namespace rawstor {
namespace ostserver {

namespace {

// Until the MDS says otherwise: its own defaults (mds/include/mds/opts.hpp).
constexpr OstRegistered default_asked{
    .heartbeat_interval = 10000,
    .info_interval = 300000,
    .info_refresh_delay = 5000,
};

// How long a stopping OST waits for the MDS to take note that it leaves.
constexpr unsigned int leave_timeout_ms = 2000;

bool cancelled(const std::exception& e) {
    auto* error = dynamic_cast<const std::system_error*>(&e);
    return error != nullptr && error->code().value() == ECANCELED;
}

} // namespace

Registrar::Registrar(
    Config config, rawstd::URI store, std::shared_ptr<MetaCache> meta_cache
) :
    _config(std::move(config)),
    _mds_location(_config.mds),
    _store(std::move(store)),
    _meta_cache(std::move(meta_cache)),
    _wake(rawstd::Pipe::Mode::NonBlocking),
    _queue(rawio::Queue::create(64)),
    _asked(default_asked) {
}

Registrar::~Registrar() = default;

void Registrar::_wake_up() noexcept {
    // A full pipe already holds a pending wake-up, so a failed write loses
    // nothing: the request itself is in the flags.
    char byte = 0;
    ssize_t ignored = write(_wake.write_fd(), &byte, 1);
    (void)ignored;
}

void Registrar::members_changed() noexcept {
    _changed = true;
    _wake_up();
}

void Registrar::stop() noexcept {
    _stop_requested = true;
    _wake_up();
}

rawstd::Task<void> Registrar::_sample() {
    try {
        std::unique_ptr<Slot> slot =
            co_await Slot::create(*_queue, _store, _meta_cache);
        RawstorLocationInfo info{};
        MemberDigest members;
        std::exception_ptr error;
        try {
            info = co_await slot->info();
            RawstdUUID token{};
            do {
                std::vector<ChunkGroup> groups;
                co_await slot->list_chunks(
                    RawstdUUID{}, rawstor_opts_list_limit(), groups, token
                );
                for (const ChunkGroup& group : groups) {
                    for (uint64_t offset : group.offsets) {
                        members.add(group.id, offset);
                    }
                }
            } while (!rawstd_uuid_is_nil(&token));
        } catch (...) {
            error = std::current_exception();
        }
        co_await slot->close();
        if (error) {
            std::rethrow_exception(error);
        }
        _info = info;
        _members = members;
        _sampled = true;
    } catch (const std::exception& e) {
        if (!cancelled(e)) {
            rawstd_warning(
                "Sampling %s failed: %s\n", _store.str().c_str(), e.what()
            );
        }
    }
    _sample_due =
        Clock::now() + std::chrono::milliseconds(_asked.info_interval);
}

rawstd::Task<void> Registrar::_register(bool leaving) {
    OstRegistration registration;
    registration.id = _config.id;
    registration.location = _config.location;
    registration.weight = _config.weight;
    registration.domain = _config.domain;
    registration.sampled = _sampled;
    registration.info = _info;
    registration.members = _members;
    registration.leaving = leaving;
    bool failed = false;
    try {
        if (!_mds) {
            _mds = co_await Slot::create(*_queue, _mds_location);
        }
        OstRegistered asked = co_await _mds->register_ost(registration);
        if (asked.heartbeat_interval != 0) {
            _asked.heartbeat_interval = asked.heartbeat_interval;
        }
        if (asked.info_interval != 0) {
            _asked.info_interval = asked.info_interval;
        }
        _asked.info_refresh_delay = asked.info_refresh_delay;
        if (!_registered && !leaving) {
            rawstd_info(
                "Registered with %s at %s in %s\n",
                printable_location(_config.mds).c_str(),
                printable_location(_config.location).c_str(),
                _config.domain.c_str()
            );
        }
        _registered = true;
        _failing = false;
    } catch (const std::exception& e) {
        // Cut short by stop(): says nothing about the MDS, and the OST is
        // still registered as far as it knows. Cut short by its deadline, it
        // is a failure like any other.
        if (!cancelled(e) || !_stop_requested) {
            if (!_failing) {
                rawstd_warning(
                    "Registration with %s failed: %s\n",
                    printable_location(_config.mds).c_str(),
                    cancelled(e) ? "no answer within a heartbeat interval"
                                 : e.what()
                );
            }
            _registered = false;
            _failing = true;
            failed = true;
        }
    }
    // The next attempt starts over on a connection of its own, not inside
    // the retries of this one.
    if (failed && _mds) {
        try {
            co_await _mds->close();
        } catch (const std::exception&) {
        }
        _mds.reset();
    }
}

rawstd::Task<void> Registrar::_sleep_until(Clock::time_point due) {
    auto now = Clock::now();
    if (due <= now) {
        co_return;
    }
    auto usec = std::min<int64_t>(
        std::chrono::ceil<std::chrono::microseconds>(due - now).count(),
        UINT_MAX
    );
    try {
        co_await _queue->timeout(static_cast<unsigned int>(usec));
    } catch (const std::system_error& e) {
        if (e.code().value() != ECANCELED) {
            throw;
        }
    }
}

rawstd::Task<void>
Registrar::_cancel_after(rawstd::Task<void>& task, unsigned int ms) {
    try {
        co_await _queue->timeout(ms * 1000);
    } catch (const std::system_error& e) {
        if (e.code().value() == ECANCELED) {
            co_return;
        }
        throw;
    }
    task.cancel_sticky();
}

rawstd::Task<void> Registrar::_wake_reader() {
    char wake_ups[64];
    while (true) {
        size_t n = 0;
        try {
            n = co_await _queue->read(
                _wake.read_fd(), wake_ups, sizeof(wake_ups)
            );
        } catch (const std::system_error& e) {
            if (e.code().value() == ECANCELED) {
                co_return;
            }
            throw;
        }
        if (n == 0) {
            co_return;
        }
        if (_stop_requested) {
            // Whatever the step: a sample of a large store takes long.
            for (std::optional<rawstd::Task<void>>* work :
                 {&_heartbeat_work, &_sample_work}) {
                if (*work && !(*work)->done()) {
                    (*work)->cancel_sticky();
                }
            }
            co_return;
        }
        if (_changed.exchange(false)) {
            // A burst of changes is sampled once, after the last of them.
            _refresh_due = Clock::now() +
                           std::chrono::milliseconds(_asked.info_refresh_delay);
            if (_sample_sleeping && _sample_work && !_sample_work->done()) {
                _sample_work->cancel();
            }
        }
    }
}

/*
 * Every heartbeat interval, whatever the sampler is doing: a sample of a
 * large store can take longer than the lease the registration keeps. Each
 * registration is given one interval, so that one stuck in the retries of an
 * MDS that is down gives way to the next, and the OST is back at most two
 * intervals after the MDS is.
 */
rawstd::Task<void> Registrar::_heartbeats() {
    while (!_stop_requested) {
        _heartbeat_work.emplace(_register(false));
        rawstd::Task<void>& registration = *_heartbeat_work;
        rawstd::Task<void> deadline =
            _cancel_after(registration, _asked.heartbeat_interval);
        co_await registration;
        deadline.cancel();
        co_await deadline;
        if (_stop_requested) {
            break;
        }
        _heartbeat_sleeping = true;
        _heartbeat_work.emplace(_sleep_until(
            Clock::now() + std::chrono::milliseconds(_asked.heartbeat_interval)
        ));
        rawstd::Task<void>& sleep = *_heartbeat_work;
        co_await sleep;
        _heartbeat_sleeping = false;
    }
    _heartbeat_work.reset();
}

// Every info interval, and one info refresh delay after a change; a new
// sample is registered at once rather than with the next heartbeat.
rawstd::Task<void> Registrar::_samples() {
    _sample_due = Clock::now();
    while (!_stop_requested) {
        auto due = _sample_due;
        if (_refresh_due) {
            due = std::min(due, *_refresh_due);
        }
        if (Clock::now() < due) {
            _sample_sleeping = true;
            _sample_work.emplace(_sleep_until(due));
            rawstd::Task<void>& sleep = *_sample_work;
            co_await sleep;
            _sample_sleeping = false;
            continue;
        }
        _refresh_due.reset();
        _sample_work.emplace(_sample());
        rawstd::Task<void>& sample = *_sample_work;
        co_await sample;
        if (_heartbeat_sleeping && _heartbeat_work &&
            !_heartbeat_work->done()) {
            _heartbeat_work->cancel();
        }
    }
    _sample_work.reset();
}

rawstd::Task<void> Registrar::_control() {
    rawstd::Task<void> samples = _samples();
    rawstd::Task<void> heartbeats = _heartbeats();
    co_await heartbeats;
    co_await samples;

    if (_registered) {
        rawstd::Task<void> leave = _register(true);
        rawstd::Task<void> deadline = _cancel_after(leave, leave_timeout_ms);
        co_await leave;
        deadline.cancel();
        co_await deadline;
        if (_registered) {
            rawstd_info("Left %s\n", printable_location(_config.mds).c_str());
        }
    }
    if (_mds) {
        try {
            co_await _mds->close();
        } catch (const std::exception& e) {
            rawstd_warning(
                "Closing %s: %s\n", printable_location(_config.mds).c_str(),
                e.what()
            );
        }
        _mds.reset();
    }
}

void Registrar::loop() {
    rawstd::Task<void> reader = _wake_reader();
    rawstd::Task<void> control = _control();
    auto pump = [this](const rawstd::Task<void>& task) {
        while (!task.done()) {
            try {
                _queue->wait();
            } catch (const std::system_error& e) {
                if (e.code().value() != EINTR) {
                    throw;
                }
            }
        }
    };
    pump(control);
    // The reader is still waiting for a byte unless it took the stop.
    reader.cancel();
    pump(reader);
    reader.get();
    control.get();
}

} // namespace ostserver
} // namespace rawstor
