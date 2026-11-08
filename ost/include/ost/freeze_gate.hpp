#ifndef RAWSTOR_OSTSERVER_FREEZE_GATE_HPP
#define RAWSTOR_OSTSERVER_FREEZE_GATE_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uuid.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <utility>

namespace rawstor {
namespace ostserver {

/*
 * The write barrier of the chunk members one rawstor-ost process serves
 * (RAWSTOR_CMD_FREEZE/THAW, docs/mds.md "Versions"). One gate is shared by
 * every worker thread, since the writers of one member may be connected to
 * any of them; its state is guarded by a std::mutex, and a coroutine that has
 * to wait suspends on its own queue and polls, so nothing blocks a thread.
 *
 * A member is a pair (object id, chunk offset). While it is frozen, enter()
 * does not return, so a write waits instead of failing. freeze() waits for
 * the writes that are already admitted. A freeze carries a lease: when it
 * runs out the member thaws by itself, so a holder that died cannot stop the
 * writers for good.
 */
class FreezeGate final {
public:
    using Clock = std::chrono::steady_clock;

    // How often a waiting coroutine looks at the gate again.
    static constexpr unsigned int poll_usec = 2000;

private:
    using Key = std::pair<RawstdUUID, uint64_t>;

    struct KeyLess {
        bool operator()(const Key& a, const Key& b) const noexcept;
    };

    struct Member {
        size_t inflight = 0;
        bool frozen = false;
        // Set once the writes admitted before the freeze are done.
        bool drained = false;
        RawstdUUID token = {};
        Clock::time_point deadline = {};
    };

    std::mutex _mu;
    std::map<Key, Member, KeyLess> _members;

    // Lifts an expired freeze and drops an idle entry; `_mu` is held.
    void _expire_locked(const Key& key, Clock::time_point now);
    void _release_idle_locked(const Key& key);

public:
    // Admits one write to the member, after any freeze of it has lifted.
    // Every enter() must be matched by one leave().
    rawstd::Task<void>
    enter(rawio::Queue& queue, const RawstdUUID& id, uint64_t offset);

    void leave(const RawstdUUID& id, uint64_t offset) noexcept;

    // Takes the member for `token` and waits until no admitted write is
    // left. Throws ETIMEDOUT, with the member thawed, when `lease` is over
    // first. A token that already holds it renews the lease; another
    // token's freeze is waited out, within `lease` too.
    rawstd::Task<void> freeze(
        rawio::Queue& queue, const RawstdUUID& id, uint64_t offset,
        const RawstdUUID& token, std::chrono::milliseconds lease
    );

    // Lifts the freeze `token` holds. Returns 0, or ESTALE when `token`
    // holds none -- its lease ran out, or it never froze.
    int thaw(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
    ) noexcept;

    // Whether `token` holds the member with every earlier write drained --
    // a freeze still waiting for them does not count.
    bool held_by(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
    ) noexcept;
};

// enter() ... leave() as a scope, for a coroutine that may throw: acquire(),
// then the destructor leaves.
class FreezeAdmission final {
private:
    FreezeGate* _gate = nullptr;
    RawstdUUID _id = {};
    uint64_t _offset = 0;

public:
    FreezeAdmission() = default;
    FreezeAdmission(const FreezeAdmission&) = delete;
    FreezeAdmission& operator=(const FreezeAdmission&) = delete;
    ~FreezeAdmission() {
        if (_gate != nullptr) {
            _gate->leave(_id, _offset);
        }
    }

    rawstd::Task<void> acquire(
        FreezeGate& gate, rawio::Queue& queue, const RawstdUUID& id,
        uint64_t offset
    ) {
        co_await gate.enter(queue, id, offset);
        _gate = &gate;
        _id = id;
        _offset = offset;
    }
};

} // namespace ostserver
} // namespace rawstor

#endif // RAWSTOR_OSTSERVER_FREEZE_GATE_HPP
