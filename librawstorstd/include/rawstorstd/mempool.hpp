#ifndef RAWSTORSTD_MEMPOOL_HPP
#define RAWSTORSTD_MEMPOOL_HPP

#include <rawstorstd/mempool.h>

#include <rawstorstd/gpp.hpp>

#include <utility>

#include <cstddef>


namespace rawstor {


template <typename T>
class MemPool {
    private:
        RawstorMemPool *_impl;

    public:
        MemPool(size_t capacity):
            _impl(rawstor_mempool_create(capacity, sizeof(T)))
        {
            if (_impl == nullptr) {
                RAWSTOR_THROW_ERRNO();
            }
        }

        MemPool(const MemPool<T> &) = delete;

        MemPool(MemPool<T> &&other) noexcept:
            _impl(std::exchange(other._impl, nullptr))
        {}

        MemPool<T>& operator=(const MemPool<T> &) = delete;

        MemPool<T>& operator=(MemPool<T> &&other) noexcept {
            if (&other != this) {
                if (_impl != nullptr) {
                    rawstor_mempool_delete(_impl);
                }

                _impl = std::exchange(other._impl, nullptr);
            }
            return *this;
        }

        ~MemPool() {
            if (_impl != nullptr) {
                rawstor_mempool_delete(_impl);
            }
        }

        inline size_t available() const noexcept {
            return rawstor_mempool_available(_impl);
        }

        inline size_t allocated() const noexcept {
            return rawstor_mempool_allocated(_impl);
        }

        inline size_t capacity() const noexcept {
            return rawstor_mempool_capacity(_impl);
        }

        inline T* data() noexcept {
            return static_cast<T*>(rawstor_mempool_data(_impl));
        }

        inline T* alloc() {
            T* ret = static_cast<T*>(rawstor_mempool_alloc(_impl));
            if (ret == nullptr) {
                RAWSTOR_THROW_ERRNO();
            }
            return ret;
        }

        inline void free(T *ptr) noexcept {
            rawstor_mempool_free(_impl, ptr);
        };
};


} // rawstor


#endif // RAWSTORSTD_MEMPOOL_HPP
