#include <ost/freeze_gate.hpp>

#include <rawio/awaitable.hpp>

#include <rawstd/logging.hpp>

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

void FreezeGate::_release_idle_locked(const Key& key) {
    auto it = _members.find(key);
    if (it != _members.end() && it->second.inflight == 0 &&
        !it->second.frozen) {
        _members.erase(it);
    }
}

void FreezeGate::_expire_locked(const Key& key, Clock::time_point now) {
    auto it = _members.find(key);
    if (it != _members.end() && it->second.frozen &&
        now >= it->second.deadline) {
        rawstd_warning("freeze of a chunk member expired, thawing it\n");
        it->second.frozen = false;
        _release_idle_locked(key);
    }
}

rawstd::Task<void> FreezeGate::enter(
    rawio::Queue& queue, const RawstdUUID& id, uint64_t offset
) {
    const Key key{id, offset};
    for (;;) {
        {
            std::lock_guard<std::mutex> guard(_mu);
            _expire_locked(key, Clock::now());
            Member& member = _members[key];
            if (!member.frozen) {
                ++member.inflight;
                co_return;
            }
        }
        co_await queue.timeout(poll_usec);
    }
}

void FreezeGate::leave(const RawstdUUID& id, uint64_t offset) noexcept {
    const Key key{id, offset};
    std::lock_guard<std::mutex> guard(_mu);
    auto it = _members.find(key);
    if (it == _members.end() || it->second.inflight == 0) {
        return;
    }
    --it->second.inflight;
    _release_idle_locked(key);
}

rawstd::Task<void> FreezeGate::freeze(
    rawio::Queue& queue, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& token, std::chrono::milliseconds lease
) {
    const Key key{id, offset};
    const Clock::time_point give_up = Clock::now() + lease;

    // Take the member.
    for (;;) {
        bool failed = false;
        {
            std::lock_guard<std::mutex> guard(_mu);
            Clock::time_point now = Clock::now();
            _expire_locked(key, now);
            Member& member = _members[key];
            if (!member.frozen ||
                rawstd_uuid_cmp(&member.token, &token) == 0) {
                member.frozen = true;
                member.token = token;
                member.deadline = now + lease;
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
            auto it = _members.find(key);
            if (it == _members.end() || !it->second.frozen ||
                rawstd_uuid_cmp(&it->second.token, &token) != 0) {
                // The lease ran out under us, and someone else may hold it.
                failed = true;
            } else if (it->second.inflight == 0) {
                co_return;
            } else if (Clock::now() >= it->second.deadline) {
                it->second.frozen = false;
                failed = true;
            }
        }
        if (failed) {
            RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
        }
        co_await queue.timeout(poll_usec);
    }
}

int FreezeGate::thaw(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
) noexcept {
    const Key key{id, offset};
    std::lock_guard<std::mutex> guard(_mu);
    _expire_locked(key, Clock::now());
    auto it = _members.find(key);
    if (it == _members.end() || !it->second.frozen ||
        rawstd_uuid_cmp(&it->second.token, &token) != 0) {
        return ESTALE;
    }
    it->second.frozen = false;
    _release_idle_locked(key);
    return 0;
}

bool FreezeGate::held_by(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& token
) noexcept {
    const Key key{id, offset};
    std::lock_guard<std::mutex> guard(_mu);
    _expire_locked(key, Clock::now());
    auto it = _members.find(key);
    return it != _members.end() && it->second.frozen &&
           rawstd_uuid_cmp(&it->second.token, &token) == 0;
}

} // namespace ostserver
} // namespace rawstor
