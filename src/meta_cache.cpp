#include "meta_cache.hpp"

#include <rawstd/uuid.h>

#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace rawstor {

bool MetaCache::Key::operator==(const Key& other) const noexcept {
    return bytes == other.bytes;
}

size_t MetaCache::KeyHash::operator()(const Key& key) const noexcept {
    return std::hash<std::string>()(key.bytes);
}

MetaCache::MetaCache(std::chrono::milliseconds ttl, size_t capacity) :
    _ttl(ttl),
    _capacity(capacity) {
}

MetaCache::Key MetaCache::_key(const RawstdUUID& id, uint64_t offset) {
    Key key;
    key.bytes.assign(reinterpret_cast<const char*>(id.bytes), sizeof(id.bytes));
    key.bytes.append(reinterpret_cast<const char*>(&offset), sizeof(offset));
    return key;
}

void MetaCache::_erase_locked(const Key& key) {
    auto it = _entries.find(key);
    if (it != _entries.end()) {
        _lru.erase(it->second.lru);
        _entries.erase(it);
    }
}

std::optional<MetaCache::Records>
MetaCache::find(const RawstdUUID& id, uint64_t offset, Ticket& ticket) {
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

void MetaCache::fill(
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
        Entry{records, std::chrono::steady_clock::now() + _ttl, _lru.begin()}
    );
}

void MetaCache::Write::_begin() {
    std::lock_guard<std::mutex> lock(_cache->_mutex);
    ++_cache->_epoch;
    ++_cache->_writing[_key];
    _cache->_erase_locked(_key);
}

void MetaCache::Write::_end() {
    std::lock_guard<std::mutex> lock(_cache->_mutex);
    ++_cache->_epoch;
    auto it = _cache->_writing.find(_key);
    if (--it->second == 0) {
        _cache->_writing.erase(it);
    }
    _cache->_erase_locked(_key);
}

MetaCache::Write::Write(
    MetaCache* cache, const RawstdUUID& id, uint64_t offset
) :
    _cache(cache) {
    if (_cache != nullptr) {
        _key = MetaCache::_key(id, offset);
        _begin();
    }
}

MetaCache::Write::~Write() {
    if (_cache != nullptr) {
        _end();
    }
}

} // namespace rawstor
