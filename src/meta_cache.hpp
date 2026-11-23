#ifndef RAWSTOR_META_CACHE_HPP
#define RAWSTOR_META_CACHE_HPP

#include <rawstd/uuid.h>

#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawstor {

/**
 * Member records of one store, kept in memory by the process that owns the
 * store (rawstor-ost), so that a client that polls a record does not make
 * the backend read it again every time (an `lvs` per call on lvm://).
 *
 * It is sound only if every change of a record in the store goes through
 * a Slot that holds this same cache: such a Slot erases the record with a
 * Write around the change (Slot does it for every mutator), and nothing
 * else writes the store. It is for the process that owns the store; a
 * client of a store that others write must not have one. The time to live
 * bounds the damage of a change made behind its back.
 *
 * Only the record of the live copy is cached, never a version's. Thread
 * safe: the lock is held for map operations only, never across a
 * suspension.
 */
class MetaCache final {
public:
    using Records = std::vector<RawstorObjectMeta>;

    // What a reader holds between the miss and the fill.
    struct Ticket {
        uint64_t epoch = 0;
        // False if a Write of the record was running at the miss.
        bool fillable = true;
    };

private:
    struct Key {
        std::string bytes;

        bool operator==(const Key& other) const noexcept {
            return bytes == other.bytes;
        }
    };

    struct KeyHash {
        size_t operator()(const Key& key) const noexcept {
            return std::hash<std::string>()(key.bytes);
        }
    };

    struct Entry {
        Records records;
        std::chrono::steady_clock::time_point expires;
        std::list<Key>::iterator lru;
    };

    static Key _key(const RawstdUUID& id, uint64_t offset) {
        Key key;
        key.bytes.assign(
            reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes)
        );
        key.bytes.append(
            reinterpret_cast<const char*>(&offset), sizeof(offset)
        );
        return key;
    }

    void _erase_locked(const Key& key) {
        auto it = _entries.find(key);
        if (it != _entries.end()) {
            _lru.erase(it->second.lru);
            _entries.erase(it);
        }
    }

    std::chrono::milliseconds _ttl;
    size_t _capacity;

    std::mutex _mutex;
    std::unordered_map<Key, Entry, KeyHash> _entries;
    // Most recently used first.
    std::list<Key> _lru;
    // The Writes running now, by record. A record with one is neither
    // answered nor filled: what the backend holds in the middle of a change
    // is not what it will hold after it.
    std::unordered_map<Key, unsigned int, KeyHash> _writing;
    // Changes whenever any record starts or ends changing. A fill is
    // accepted only if it has not moved since the read began: a read that
    // began before a change began, or ended after it ended, would otherwise
    // store the record from before it.
    uint64_t _epoch = 0;

public:
    explicit MetaCache(
        std::chrono::milliseconds ttl, size_t capacity = 16 * 1024
    ) :
        _ttl(ttl),
        _capacity(capacity) {}

    MetaCache(const MetaCache&) = delete;
    MetaCache& operator=(const MetaCache&) = delete;

    /**
     * The cached records, or nothing, in which case `ticket` is for the
     * fill() that follows the read of the backend.
     */
    std::optional<Records>
    find(const RawstdUUID& id, uint64_t offset, Ticket& ticket) {
        Key key = _key(id, offset);
        std::lock_guard<std::mutex> lock(_mutex);
        ticket.epoch = _epoch;
        ticket.fillable = _writing.find(key) == _writing.end();
        if (!ticket.fillable) {
            return std::nullopt;
        }
        auto it = _entries.find(key);
        if (it == _entries.end()) {
            return std::nullopt;
        }
        if (std::chrono::steady_clock::now() >= it->second.expires) {
            _erase_locked(key);
            return std::nullopt;
        }
        _lru.splice(_lru.begin(), _lru, it->second.lru);
        return it->second.records;
    }

    void fill(
        const RawstdUUID& id, uint64_t offset, const Ticket& ticket,
        const Records& records
    ) {
        Key key = _key(id, offset);
        std::lock_guard<std::mutex> lock(_mutex);
        if (!ticket.fillable || ticket.epoch != _epoch) {
            return;
        }
        _erase_locked(key);
        while (!_entries.empty() && _entries.size() >= _capacity) {
            _entries.erase(_lru.back());
            _lru.pop_back();
        }
        _lru.push_front(key);
        _entries.emplace(
            std::move(key),
            Entry{
                records, std::chrono::steady_clock::now() + _ttl, _lru.begin()
            }
        );
    }

    /**
     * A change of the record of (id, offset) in the backend. Kept around
     * the call that changes the backend, whether it succeeds or throws --
     * after a failure the record on the disk is not known. While it lives
     * the record is neither answered from the cache nor stored in it, and
     * what was stored is erased on both sides of it.
     */
    class Write final {
    private:
        MetaCache* _cache;
        Key _key;

        void _begin() {
            std::lock_guard<std::mutex> lock(_cache->_mutex);
            ++_cache->_epoch;
            ++_cache->_writing[_key];
            _cache->_erase_locked(_key);
        }

        void _end() {
            std::lock_guard<std::mutex> lock(_cache->_mutex);
            ++_cache->_epoch;
            auto it = _cache->_writing.find(_key);
            if (--it->second == 0) {
                _cache->_writing.erase(it);
            }
            _cache->_erase_locked(_key);
        }

    public:
        Write(MetaCache* cache, const RawstdUUID& id, uint64_t offset) :
            _cache(cache) {
            if (_cache != nullptr) {
                _key = MetaCache::_key(id, offset);
                _begin();
            }
        }

        Write(const Write&) = delete;
        Write& operator=(const Write&) = delete;

        ~Write() {
            if (_cache != nullptr) {
                _end();
            }
        }
    };
};

} // namespace rawstor

#endif
