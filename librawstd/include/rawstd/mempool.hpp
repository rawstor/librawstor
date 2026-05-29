#ifndef RAWSTD_MEMPOOL_HPP
#define RAWSTD_MEMPOOL_HPP

#include <rawstd/mempool.h>

#include <rawstd/gpp.hpp>

#include <utility>

#include <cstddef>

namespace rawstd {

template <typename T>
class MemPool {
private:
    RawstdMemPool* _impl;

public:
    MemPool(size_t capacity) :
        _impl(rawstd_mempool_create(capacity, sizeof(T))) {
        if (_impl == nullptr) {
            RAWSTD_THROW_ERRNO();
        }
    }

    MemPool(const MemPool<T>&) = delete;

    MemPool(MemPool<T>&& other) noexcept :
        _impl(std::exchange(other._impl, nullptr)) {}

    MemPool<T>& operator=(const MemPool<T>&) = delete;

    MemPool<T>& operator=(MemPool<T>&& other) noexcept {
        if (&other != this) {
            if (_impl != nullptr) {
                rawstd_mempool_delete(_impl);
            }

            _impl = std::exchange(other._impl, nullptr);
        }
        return *this;
    }

    ~MemPool() {
        if (_impl != nullptr) {
            rawstd_mempool_delete(_impl);
        }
    }

    inline size_t available() const noexcept {
        return rawstd_mempool_available(_impl);
    }

    inline size_t allocated() const noexcept {
        return rawstd_mempool_allocated(_impl);
    }

    inline size_t capacity() const noexcept {
        return rawstd_mempool_capacity(_impl);
    }

    inline T* data() noexcept {
        return static_cast<T*>(rawstd_mempool_data(_impl));
    }

    inline T* alloc() {
        T* ret = static_cast<T*>(rawstd_mempool_alloc(_impl));
        if (ret == nullptr) {
            RAWSTD_THROW_ERRNO();
        }
        return ret;
    }

    inline void free(T* ptr) noexcept { rawstd_mempool_free(_impl, ptr); };
};

} // namespace rawstd

#endif // RAWSTD_MEMPOOL_HPP
