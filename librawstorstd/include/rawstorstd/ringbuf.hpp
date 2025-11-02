#ifndef RAWSTORSTD_RINGBUF_HPP
#define RAWSTORSTD_RINGBUF_HPP

#include <rawstorstd/gpp.hpp>

#include <memory>
#include <stdexcept>
#include <vector>


namespace rawstor {


template <typename T>
class RingBuf {
    private:
        std::vector<std::unique_ptr<T>> _data;
        size_t _head;
        size_t _tail;
        size_t _count;

    public:
        RingBuf(size_t capacity):
            _data(capacity),
            _head(0),
            _tail(0),
            _count(0)
        {}

        RingBuf(const RingBuf<T> &) = delete;
        RingBuf(RingBuf<T> &&other) = delete;

        RingBuf<T>& operator=(const RingBuf<T> &) = delete;
        RingBuf<T>& operator=(RingBuf<T> &&other) = delete;

        inline bool empty() const noexcept {
            return _count == 0;
        }

        inline bool full() const noexcept {
            return _count == _data.size();
        }

        inline size_t capacity() const noexcept {
            return _data.size();
        }

        inline size_t size() const noexcept {
            return _count;
        }

        inline void push(std::unique_ptr<T> item) {
            if (full()) {
                RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
            }
            _data[_head] = std::move(item);
            _head = (_head + 1) % _data.size();
            ++_count;
        }

        inline const T& tail() const {
            if (empty()) {
                throw std::out_of_range("RingBuf is empty");
            }
            return *_data[_tail].get();
        }

        inline std::unique_ptr<T> pop() {
            if (empty()) {
                throw std::out_of_range("RingBuf is empty");
            }
            std::unique_ptr<T> item = std::exchange(_data[_tail], nullptr);
            _tail = (_tail + 1) % _data.size();
            --_count;
            return std::move(item);
        }
};


} // rawstor


#endif // RAWSTORSTD_RINGBUF_HPP
