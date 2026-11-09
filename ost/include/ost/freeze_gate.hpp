#ifndef RAWSTOR_OSTSERVER_FREEZE_GATE_HPP
#define RAWSTOR_OSTSERVER_FREEZE_GATE_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uuid.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

namespace rawstor {
namespace ostserver {

/*
 * The write barrier of the chunk members one rawstor-ost process serves
 * (RAWSTOR_CMD_FREEZE/THAW, docs/mds.md "The write barrier"). One gate is
 * shared by every worker thread, since the writers of one member may be
 * connected to any of them.
 *
 * A member is a pair (object id, chunk offset). A session looks its Member up
 * once, when it opens the member, and keeps it; a write then passes the
 * barrier with try_enter(): one atomic operation, no lock, no allocation, no
 * coroutine. Only a write that finds the member frozen goes on to wait(),
 * which suspends on its own queue and polls, so nothing blocks a thread.
 *
 * A freeze carries a lease: when it runs out the member thaws by itself, so a
 * holder that died cannot stop the writers for good.
 */
class FreezeGate final {
public:
    using Clock = std::chrono::steady_clock;

    // How often a waiting coroutine looks at its member again.
    static constexpr unsigned int poll_usec = 2000;

    class Member final {
    private:
        friend class FreezeGate;

        // The top bit is "frozen", the rest counts the writes admitted and not
        // yet finished. One word, so that a write either is counted before a
        // freeze sets the bit (and the freeze waits for it) or sees the bit and
        // stays out: there is no window in between.
        static constexpr uint64_t frozen_bit = uint64_t(1) << 63;

        std::atomic<uint64_t> _word{0};

        // Guards the fields below, which only the slow paths touch.
        std::mutex _mu;
        RawstdUUID _token = {};
        // Set once the writes admitted before the freeze are done.
        bool _drained = false;
        Clock::time_point _deadline = {};

        // Lifts an expired freeze; `_mu` is held.
        void _expire_locked(Clock::time_point now);

    public:
        // Admits one write if the member is not frozen. Every admission must
        // be matched by one leave().
        bool try_enter() noexcept {
            uint64_t before = _word.fetch_add(1, std::memory_order_acq_rel);
            if ((before & frozen_bit) == 0) {
                return true;
            }
            _word.fetch_sub(1, std::memory_order_acq_rel);
            return false;
        }

        void leave() noexcept { _word.fetch_sub(1, std::memory_order_release); }

        // Admits one write, after any freeze of the member has lifted.
        rawstd::Task<void> wait(rawio::Queue& queue);

        // Takes the member for `token` and waits until no admitted write is
        // left. Throws ETIMEDOUT, with the member thawed, when `lease` is over
        // first. A token that already holds it renews the lease; another
        // token's freeze is waited out, within `lease` too.
        rawstd::Task<void> freeze(
            rawio::Queue& queue, const RawstdUUID& token,
            std::chrono::milliseconds lease
        );

        // Lifts the freeze `token` holds. Returns 0, or ESTALE when `token`
        // holds none -- its lease ran out, or it never froze.
        int thaw(const RawstdUUID& token) noexcept;

        // Whether `token` holds the member with every earlier write drained --
        // a freeze still waiting for them does not count.
        bool held_by(const RawstdUUID& token) noexcept;
    };

    using MemberRef = std::shared_ptr<Member>;

private:
    using Key = std::pair<RawstdUUID, uint64_t>;

    struct KeyLess {
        bool operator()(const Key& a, const Key& b) const noexcept;
    };

    std::mutex _mu;
    // Strong references: a member that is frozen must outlive the call that
    // froze it, and nobody else need hold it. Members nobody holds, that are
    // not frozen and have no write in flight, are dropped by _sweep_locked().
    std::map<Key, MemberRef, KeyLess> _members;
    size_t _sweep_at = 64;

    void _sweep_locked();

public:
    // The member of `id`/`offset`, created if there is none.
    MemberRef member(const RawstdUUID& id, uint64_t offset);

    // The same by name, for the requests that carry one (FREEZE, THAW,
    // CREATE_VERSION). thaw() and held_by() never create a member.
    rawstd::Task<void> freeze(
        rawio::Queue& queue, const RawstdUUID& id, uint64_t offset,
        const RawstdUUID& token, std::chrono::milliseconds lease
    );

    int thaw(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
    ) noexcept;

    bool held_by(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
    ) noexcept;
};

// One admitted write, as a scope: try_enter() or wait(), then the destructor
// leaves. The fast path is the synchronous try_enter(); wait() is a coroutine
// only the writes that meet a frozen member pay for.
class FreezeAdmission final {
private:
    FreezeGate::Member* _member = nullptr;

public:
    FreezeAdmission() = default;
    FreezeAdmission(const FreezeAdmission&) = delete;
    FreezeAdmission& operator=(const FreezeAdmission&) = delete;
    ~FreezeAdmission() {
        if (_member != nullptr) {
            _member->leave();
        }
    }

    bool try_enter(FreezeGate::Member& member) noexcept {
        if (member.try_enter()) {
            _member = &member;
            return true;
        }
        return false;
    }

    rawstd::Task<void> wait(FreezeGate::Member& member, rawio::Queue& queue) {
        co_await member.wait(queue);
        _member = &member;
    }
};

} // namespace ostserver
} // namespace rawstor

#endif // RAWSTOR_OSTSERVER_FREEZE_GATE_HPP
