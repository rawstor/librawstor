#include <ost/freeze_gate.hpp>

#include <rawio/awaitable.hpp>

#include <rawstd/logging.hpp>

#include <algorithm>
#include <system_error>

#include <cerrno>
#include <cstring>

namespace rawstor {
namespace ostserver {

bool FreezeGate::KeyLess::operator()(
    const Key& a, const Key& b
) const noexcept {
    int cmp = memcmp(a.first.bytes, b.first.bytes, sizeof(a.first.bytes));
    if (cmp != 0) {
        return cmp < 0;
    }
    return a.second < b.second;
}

void FreezeGate::Member::_expire_locked(Clock::time_point now) {
    uint64_t word = _word.load(std::memory_order_acquire);
    if ((word & frozen_bit) != 0 && now >= _deadline) {
        rawstd_warning("freeze of a chunk member expired, thawing it\n");
        _word.fetch_and(~frozen_bit, std::memory_order_acq_rel);
        _drained = false;
    }
}

rawstd::Task<void> FreezeGate::Member::wait(rawio::Queue& queue) {
    for (;;) {
        {
            std::lock_guard<std::mutex> guard(_mu);
            _expire_locked(Clock::now());
        }
        if (try_enter()) {
            co_return;
        }
        co_await queue.timeout(poll_usec);
    }
}

rawstd::Task<void> FreezeGate::Member::freeze(
    rawio::Queue& queue, const RawstdUUID& token,
    std::chrono::milliseconds lease
) {
    const Clock::time_point give_up = Clock::now() + lease;

    // Take the member.
    for (;;) {
        bool failed = false;
        {
            std::lock_guard<std::mutex> guard(_mu);
            Clock::time_point now = Clock::now();
            _expire_locked(now);
            uint64_t word = _word.load(std::memory_order_acquire);
            bool frozen = (word & frozen_bit) != 0;
            if (!frozen || rawstd_uuid_cmp(&_token, &token) == 0) {
                // A renewal keeps what the first freeze already drained.
                _drained = frozen && _drained && (word & ~frozen_bit) == 0;
                _token = token;
                _deadline = now + lease;
                _word.fetch_or(frozen_bit, std::memory_order_acq_rel);
                break;
            }
            failed = now >= give_up;
        }
        if (failed) {
            RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
        }
        co_await queue.timeout(poll_usec);
    }

    // Wait for the writes that were admitted before it.
    for (;;) {
        bool failed = false;
        {
            std::lock_guard<std::mutex> guard(_mu);
            uint64_t word = _word.load(std::memory_order_acquire);
            if ((word & frozen_bit) == 0 ||
                rawstd_uuid_cmp(&_token, &token) != 0) {
                // The lease ran out under us, and someone else may hold it.
                failed = true;
            } else if ((word & ~frozen_bit) == 0) {
                _drained = true;
                co_return;
            } else if (Clock::now() >= _deadline) {
                _word.fetch_and(~frozen_bit, std::memory_order_acq_rel);
                _drained = false;
                failed = true;
            }
        }
        if (failed) {
            RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
        }
        co_await queue.timeout(poll_usec);
    }
}

int FreezeGate::Member::thaw(const RawstdUUID& token) noexcept {
    std::lock_guard<std::mutex> guard(_mu);
    _expire_locked(Clock::now());
    uint64_t word = _word.load(std::memory_order_acquire);
    if ((word & frozen_bit) == 0 || rawstd_uuid_cmp(&_token, &token) != 0) {
        return ESTALE;
    }
    _word.fetch_and(~frozen_bit, std::memory_order_acq_rel);
    _drained = false;
    return 0;
}

bool FreezeGate::Member::held_by(const RawstdUUID& token) noexcept {
    std::lock_guard<std::mutex> guard(_mu);
    _expire_locked(Clock::now());
    uint64_t word = _word.load(std::memory_order_acquire);
    return (word & frozen_bit) != 0 && _drained &&
           rawstd_uuid_cmp(&_token, &token) == 0;
}

void FreezeGate::_sweep_locked() {
    const Clock::time_point now = Clock::now();
    for (auto it = _members.begin(); it != _members.end();) {
        Member& member = *it->second;
        // Only the registry holds it: nobody can take another reference
        // without `_mu`, which is held.
        if (it->second.use_count() == 1) {
            // A freeze nobody touches any more still has to run out. The
            // lock is let go of before the member can be erased with it.
            {
                std::unique_lock<std::mutex> guard(
                    member._mu, std::try_to_lock
                );
                if (guard.owns_lock()) {
                    member._expire_locked(now);
                }
            }
            if (member._word.load(std::memory_order_acquire) == 0) {
                it = _members.erase(it);
                continue;
            }
        }
        ++it;
    }
    _sweep_at = std::max<size_t>(64, 2 * _members.size());
}

FreezeGate::MemberRef
FreezeGate::member(const RawstdUUID& id, uint64_t offset) {
    const Key key{id, offset};
    std::lock_guard<std::mutex> guard(_mu);
    auto it = _members.find(key);
    if (it != _members.end()) {
        return it->second;
    }
    if (_members.size() >= _sweep_at) {
        _sweep_locked();
    }
    MemberRef created = std::make_shared<Member>();
    _members.emplace(key, created);
    return created;
}

rawstd::Task<void> FreezeGate::freeze(
    rawio::Queue& queue, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& token, std::chrono::milliseconds lease
) {
    // Held for the whole call, so a sweep cannot drop it before it is frozen.
    MemberRef held = member(id, offset);
    co_await held->freeze(queue, token, lease);
}

int FreezeGate::thaw(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
) noexcept {
    MemberRef held;
    {
        std::lock_guard<std::mutex> guard(_mu);
        auto it = _members.find(Key{id, offset});
        if (it == _members.end()) {
            return ESTALE;
        }
        held = it->second;
    }
    return held->thaw(token);
}

bool FreezeGate::held_by(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
) noexcept {
    MemberRef held;
    {
        std::lock_guard<std::mutex> guard(_mu);
        auto it = _members.find(Key{id, offset});
        if (it == _members.end()) {
            return false;
        }
        held = it->second;
    }
    return held->held_by(token);
}

} // namespace ostserver
} // namespace rawstor
