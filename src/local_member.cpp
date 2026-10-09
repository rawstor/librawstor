#include "local_member.hpp"

#include <algorithm>
#include <exception>
#include <map>
#include <mutex>
#include <string>
#include <tuple>

namespace {

const uint64_t sector_size = 512;
const uint64_t region_sectors = 2048;

bool overlaps(uint64_t a, uint64_t b, uint64_t c, uint64_t d) noexcept {
    return a < d && c < b;
}

} // namespace

namespace rawstor {

void LocalMember::learn_epoch(uint64_t epoch) noexcept {
    uint64_t known = _epoch.load();
    while (known < epoch && !_epoch.compare_exchange_weak(known, epoch)) {
    }
}

bool LocalMember::admit(uint64_t epoch, uint64_t& generation) noexcept {
    if (epoch == 0) {
        return true;
    }
    for (;;) {
        uint64_t g = _generation.load();
        if (epoch < _epoch.load()) {
            return false;
        }
        ++_admitted[g & 1];
        // A raise_epoch() that moved on meanwhile may already have checked
        // this generation: count again under the new one instead.
        if (_generation.load() == g) {
            generation = g;
            return true;
        }
        release(g);
    }
}

void LocalMember::release(uint64_t generation) noexcept {
    if (--_admitted[generation & 1] == 0) {
        std::lock_guard<std::mutex> guard(_drain_mu);
        _drain_waiters.notify_all();
    }
}

rawstd::Task<bool>
LocalMember::raise_epoch(rawio::Queue& queue, uint64_t epoch) {
    if (epoch <= _epoch.load()) {
        co_return false;
    }
    _epoch.store(epoch);
    uint64_t old = _generation.fetch_add(1);
    if (_admitted[old & 1].load() == 0) {
        co_return false;
    }
    record.unlock();
    std::exception_ptr error;
    try {
        co_await _drain_waiters.wait(queue, _drain_mu, [this, old]() {
            return _admitted[old & 1].load() == 0;
        });
    } catch (...) {
        error = std::current_exception();
    }
    co_await record.lock(queue);
    if (error) {
        std::rethrow_exception(error);
    }
    co_return true;
}

void LocalMember::follow_role(RawstorObjectMemberRole role) noexcept {
    std::lock_guard<std::mutex> guard(_resync_mu);
    if (role == RAWSTOR_OBJECT_MEMBER_SYNCING) {
        if (!_syncing.load()) {
            _written.clear();
            _syncing.store(true);
        }
    } else {
        _syncing.store(false);
        _written.clear();
    }
}

rawstd::Task<void>
LocalMember::client_write(rawio::Queue& queue, uint64_t offset, uint64_t size) {
    if (!_syncing.load() || size == 0) {
        co_return;
    }
    uint64_t end = offset + size;
    co_await _resync_waiters.wait(queue, _resync_mu, [&]() {
        if (!_syncing.load()) {
            return true;
        }
        for (const auto& [b, e] : _resyncing) {
            if (overlaps(offset, end, b, e)) {
                return false;
            }
        }
        // Whole sectors only.
        uint64_t first = (offset + sector_size - 1) / sector_size;
        uint64_t last = end / sector_size;
        for (uint64_t s = first; s < last; ++s) {
            std::vector<uint64_t>& bits = _written[s / region_sectors];
            if (bits.empty()) {
                bits.assign(region_sectors / 64, 0);
            }
            uint64_t i = s % region_sectors;
            bits[i / 64] |= 1ull << (i % 64);
        }
        return true;
    });
}

bool LocalMember::resync_begin(uint64_t offset, uint64_t size, Ranges& runs) {
    uint64_t end = offset + size;
    runs.clear();
    std::lock_guard<std::mutex> guard(_resync_mu);
    if (!_syncing.load()) {
        return false;
    }
    _resyncing.emplace_back(offset, end);

    uint64_t run = offset;
    uint64_t pos = offset;
    while (pos < end) {
        uint64_t s = pos / sector_size;
        uint64_t next = std::min(end, (s + 1) * sector_size);
        bool written = false;
        auto it = _written.find(s / region_sectors);
        if (it != _written.end()) {
            uint64_t i = s % region_sectors;
            written = (it->second[i / 64] >> (i % 64)) & 1;
        }
        if (written) {
            if (run < pos) {
                runs.emplace_back(run, pos);
            }
            run = next;
        }
        pos = next;
    }
    if (run < end) {
        runs.emplace_back(run, end);
    }
    return true;
}

void LocalMember::resync_end(uint64_t offset, uint64_t size) noexcept {
    std::lock_guard<std::mutex> guard(_resync_mu);
    for (auto it = _resyncing.begin(); it != _resyncing.end(); ++it) {
        if (it->first == offset && it->second == offset + size) {
            _resyncing.erase(it);
            break;
        }
    }
    _resync_waiters.notify_all();
}

std::shared_ptr<LocalMember> local_member(
    const rawstd::URI& location, const RawstdUUID& id, uint64_t offset
) {
    using Key = std::tuple<std::string, std::string, uint64_t>;
    static std::mutex registry_mu;
    static std::map<Key, std::weak_ptr<LocalMember>> registry;

    Key key{
        location.str(),
        std::string(reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)),
        offset
    };

    std::lock_guard<std::mutex> guard(registry_mu);
    for (auto it = registry.begin(); it != registry.end();) {
        it = it->second.expired() ? registry.erase(it) : std::next(it);
    }
    std::weak_ptr<LocalMember> slot = registry[key];
    std::shared_ptr<LocalMember> ret = slot.lock();
    if (!ret) {
        ret = std::make_shared<LocalMember>();
        registry[key] = ret;
    }
    return ret;
}

} // namespace rawstor
