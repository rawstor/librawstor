#ifndef RAWSTOR_OSTSERVER_REGISTRAR_HPP
#define RAWSTOR_OSTSERVER_REGISTRAR_HPP

#include "ost_registration.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/pipe.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

namespace rawstor {

class MetaCache;
class Slot;

namespace ostserver {

/*
 * Keeps this OST in the topology of the MDS of its cluster (docs/mds.md, "OST
 * registration"), on a thread of its own: registers with the MDS, again every
 * heartbeat interval the MDS asks for, and with each registration sends the
 * latest sample of the store it serves -- its space and its member digest. A
 * sample is taken at start, every info interval, and one info refresh delay
 * after the last of a burst of members_changed(). stop() registers the OST
 * as leaving and ends loop(); stop() and members_changed() may be called from
 * any thread, stop() from a signal handler too.
 */
class Registrar final {
public:
    using Clock = std::chrono::steady_clock;

    struct Config {
        RawstdUUID id{};
        // The MDS of the cluster, mds://host:port.
        std::string mds;
        // Where the clients reach the store, as the MDS hands it out.
        std::string location;
        uint64_t weight = 0;
        // "[[[dc/]row/]rack/]server".
        std::string domain;
    };

private:
    Config _config;
    rawstd::URI _mds_location;
    rawstd::URI _store;
    std::shared_ptr<MetaCache> _meta_cache;
    rawstd::Pipe _wake;
    std::unique_ptr<rawio::Queue> _queue;
    std::atomic<bool> _stop_requested{false};
    std::atomic<bool> _changed{false};

    // What the MDS asked for last, until it answers.
    OstRegistered _asked;
    std::unique_ptr<Slot> _mds;
    bool _sampled = false;
    RawstorLocationInfo _info{};
    MemberDigest _members;
    Clock::time_point _sample_due;
    std::optional<Clock::time_point> _refresh_due;
    // Whether the last registration went through; only a change is logged.
    bool _registered = false;
    bool _failing = false;

    // The step _control() is waiting for, and whether it is a sleep: a
    // change wakes a sleep up, a stop cuts any step short.
    std::optional<rawstd::Task<void>> _work;
    bool _sleeping = false;

    rawstd::Task<void> _sample();
    rawstd::Task<void> _register(bool leaving);
    rawstd::Task<void> _sleep_until(Clock::time_point due);
    rawstd::Task<void> _cancel_after(rawstd::Task<void>& task, unsigned int ms);
    rawstd::Task<void> _wake_reader();
    rawstd::Task<void> _control();
    void _wake_up() noexcept;

public:
    // `store` is the one location this OST serves, read with `meta_cache`
    // like the Slots of its Servers.
    Registrar(
        Config config, rawstd::URI store, std::shared_ptr<MetaCache> meta_cache
    );
    Registrar(const Registrar&) = delete;
    Registrar& operator=(const Registrar&) = delete;
    ~Registrar();

    void loop();
    void members_changed() noexcept;
    void stop() noexcept;
};

} // namespace ostserver
} // namespace rawstor

#endif // RAWSTOR_OSTSERVER_REGISTRAR_HPP
