#ifndef RAWSTORSTD_RINGBUF_HPP
#define RAWSTORSTD_RINGBUF_HPP

#include <rawstorstd/ringbuf.h>

#include <rawstorstd/gpp.hpp>

#include <type_traits>
#include <utility>

#include <cstddef>


namespace rawstor {


template <typename T>
class RingBufIter {
    private:
        RawstorRingBuf *_buf;
        void *_iter;

    public:
        RingBufIter(RawstorRingBuf *buf, void *iter) noexcept:
            _buf(buf),
            _iter(iter)
        {}

        RingBufIter(const RingBufIter &other) noexcept:
            _buf(other._buf),
            _iter(other._iter)
        {}

        RingBufIter(RingBufIter &&other) noexcept:
            _buf(std::move(other._buf)),
            _iter(std::move(other._iter))
        {}

        inline RingBufIter<T>& operator=(const RingBufIter<T> &other) noexcept {
            if (&other != this) {
                _buf = other._buf;
                _iter = other._iter;
            }
            return *this;
        }

        inline RingBufIter<T>& operator=(RingBufIter<T> &&other) noexcept {
            if (&other != this) {
                _buf = std::move(other._buf);
                _iter = std::move(other._iter);
            }
            return *this;
        }

        inline bool operator!=(const RingBufIter<T> &other) noexcept {
            return _iter != other._iter;
        }

        inline RingBufIter<T>& operator++() noexcept {
            _iter = rawstor_ringbuf_next(_buf, _iter);
            return *this;
        }

        inline T& operator*() noexcept {
            return *static_cast<T*>(_iter);
        }
};


template <typename T>
class RingBuf {
    static_assert(
        std::is_trivially_destructible<T>::value,
        "RingBuf only supports trivially destructible types");

    private:
        RawstorRingBuf *_impl;

    public:
        using Iterator = RingBufIter<T>;

        RingBuf(size_t capacity):
            _impl(rawstor_ringbuf_create(capacity, sizeof(T)))
        {
            if (_impl == nullptr) {
                RAWSTOR_THROW_ERRNO();
            }
        }

        RingBuf(const RingBuf<T> &) = delete;

        RingBuf(RingBuf<T> &&other) noexcept:
            _impl(std::exchange(other._impl, nullptr))
        {}

        RingBuf<T>& operator=(const RingBuf<T> &) = delete;

        RingBuf<T>& operator=(RingBuf<T> &&other) noexcept {
            if (&other != this) {
                if (_impl != nullptr) {
                    rawstor_ringbuf_delete(_impl);
                }

                _impl = std::exchange(other._impl, nullptr);
            }
            return *this;
        }

        ~RingBuf() {
            if (_impl != nullptr) {
                rawstor_ringbuf_delete(_impl);
            }
        }

        inline bool empty() const noexcept {
            return rawstor_ringbuf_empty(_impl);
        }

        inline size_t capacity() const noexcept {
            return rawstor_ringbuf_capacity(_impl);
        }

        inline size_t size() const noexcept {
            return rawstor_ringbuf_size(_impl);
        }

        inline T& head() noexcept {
            return *static_cast<T*>(rawstor_ringbuf_head(_impl));
        }

        inline T& tail() {
            return *static_cast<T*>(rawstor_ringbuf_tail(_impl));
        }

        inline void push() {
            int res = rawstor_ringbuf_push(_impl);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        inline void pop() {
            int res = rawstor_ringbuf_pop(_impl);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        inline RingBuf<T>::Iterator begin() {
            return RingBuf<T>::Iterator(_impl, rawstor_ringbuf_iter(_impl));
        }

        inline RingBuf<T>::Iterator end() {
            return RingBuf<T>::Iterator(_impl, nullptr);
        }
};


} // rawstor


#endif // RAWSTORSTD_RINGBUF_HPP
