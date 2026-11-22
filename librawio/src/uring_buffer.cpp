#include "uring_buffer.hpp"

#include "uring_queue.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <sys/mman.h>

#include <cassert>
#include <cstring>

#include <algorithm>
#include <bit>
#include <memory>
#include <new>
#include <sstream>
#include <utility>
#include <vector>

namespace rawio {
namespace uring {

BufferRingEntry::BufferRingEntry(
    BufferRing* owner, io_uring_buf_ring* buf_ring, void* data, size_t size,
    size_t result, unsigned int index, int mask
) :
    _owner(owner),
    _buf_ring(buf_ring),
    _data(data),
    _size(size),
    _result(result),
    _index(index),
    _mask(mask) {
}

BufferRingEntry::~BufferRingEntry() {
    io_uring_buf_ring_add(_buf_ring, _data, _size, _index, _mask, 0);
    io_uring_buf_ring_advance(_buf_ring, 1);
    _owner->on_release();
}

__u16 BufferRing::_id_counter = 0;

BufferRing::BufferRing(
    Queue& q, io_uring& ring, size_t entry_size, unsigned int entries
) :
    _q(q),
    _ring(ring),
    _entry_size(entry_size),
    _entry_shift(std::countr_zero(entry_size)),
    _entries(entries),
    _fd(-1),
    _flags(0),
    _free(entries),
    _starved(false),
    _cancel_requested(false),
    _id(++_id_counter),
    _buf_ring(nullptr),
    _buf_ring_size(
        sizeof(struct io_uring_buf) * entries + entry_size * entries
    ),
    _mask(io_uring_buf_ring_mask(entries)),
    _entries_base(nullptr),
    _pending_offset(0),
    _pending_size(0),
    _pending_entries(entries),
    _waiter(),
    _waiter_want(0),
    _waiter_item(nullptr),
    _waiter_error(nullptr),
    _has_terminal(false),
    _terminal_error(0),
    _closed(false),
    _event(nullptr) {

    assert((_entry_size & (_entry_size - 1)) == 0);
    assert((entries & (entries - 1)) == 0);

    _buf_ring = static_cast<io_uring_buf_ring*>(mmap(
        nullptr, _buf_ring_size, PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE, 0, 0
    ));
    if (_buf_ring == MAP_FAILED) {
        throw std::bad_alloc();
    }
    _entries_base =
        reinterpret_cast<char*>(_buf_ring) + sizeof(io_uring_buf) * entries;

    try {
        io_uring_buf_ring_init(_buf_ring);

        io_uring_buf_reg reg{};
        reg.ring_addr = reinterpret_cast<__u64>(_buf_ring);
        reg.ring_entries = entries;
        reg.bgid = _id;

        // TODO: Replace with io_uring_setup_buf_ring()?
        int res = io_uring_register_buf_ring(&_ring, &reg, 0);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        for (unsigned int i = 0; i < entries; ++i) {
            io_uring_buf_ring_add(
                _buf_ring, _get_entry(i), _entry_size, i, _mask, i
            );
        }

        io_uring_buf_ring_advance(_buf_ring, entries);
    } catch (...) {
        munmap(_buf_ring, _buf_ring_size);
        throw;
    }
}

BufferRing::~BufferRing() {
    _closed = true;
    while (!_pending_entries.empty()) {
        _pending_entries.pop();
    }

    munmap(_buf_ring, _buf_ring_size);
    int res = io_uring_unregister_buf_ring(&_ring, _id);
    if (res < 0) {
        rawstd_error(
            "io_uring_unregister_buf_ring() failed: %s\n", strerror(-res)
        );
    }
    // TODO: Call io_uring_free_buf_ring() if we are going to use
    // io_uring_setup_buf_ring()
}

void* BufferRing::_get_entry(unsigned int index) {
    return _entries_base + (index << _entry_shift);
}

unsigned int BufferRing::id() const noexcept {
    return _id;
}

void BufferRing::_extract(size_t want, rawio::RecvStream::Item& out) {
    auto entries =
        std::make_shared<std::list<std::unique_ptr<BufferRingEntry>>>();
    std::vector<iovec> iov;
    size_t iov_size = 0;
    iov.reserve(_pending_entries.size());

    while (!_pending_entries.empty() && want) {
        BufferRingEntry& e = _pending_entries.tail();
        void* e_data = static_cast<char*>(e.data()) + _pending_offset;
        size_t e_size = e.result() - _pending_offset;
        if (e_size <= want - iov_size) [[likely]] {
            iov.push_back({.iov_base = e_data, .iov_len = e_size});
            _pending_offset = 0;
            _pending_size -= e_size;
            entries->push_back(_pending_entries.pop());
            iov_size += e_size;
            if (iov_size == want) {
                break;
            }
        } else {
            iov.push_back({.iov_base = e_data, .iov_len = want - iov_size});
            _pending_offset += iov.back().iov_len;
            _pending_size -= iov.back().iov_len;
            iov_size += iov.back().iov_len;
            break;
        }
    }

    out = rawio::RecvStream::Item(std::move(iov), iov_size, std::move(entries));
}

void BufferRing::on_arrival(int result, unsigned int flags) {
    if (_closed) {
        return;
    }

    if (result > 0 && (flags & IORING_CQE_F_BUFFER)) {
        unsigned int index = flags >> IORING_CQE_BUFFER_SHIFT;
        std::unique_ptr<BufferRingEntry> pending_entry =
            std::make_unique<BufferRingEntry>(
                this, _buf_ring, _get_entry(index), _entry_size, result, index,
                _mask
            );
        --_free;
        _pending_size += result;
        _pending_entries.push(std::move(pending_entry));
    }

    if (result == 0) {
        result = -EPIPE;
    }

    // A registration that was asked to stop ends by ENOBUFS as well when the
    // ring has no buffer left.
    if (_cancel_requested && result == -ENOBUFS) {
        result = -ECANCELED;
    }

    // ENOBUFS is not an error of the stream: the kernel ended the
    // registration because the ring had no free buffer, and what it could not
    // take is still in the socket, held back by the TCP window.
    if (result < 0 && result != -ENOBUFS && !_has_terminal) {
        _has_terminal = true;
        _terminal_error = -result;
    }

    // Without IORING_CQE_F_MORE the kernel has ended the registration on its
    // own, even if this completion still carries data (the ring ran out of
    // buffers, or it couldn't post the next completion to a full completion
    // ring). It is submitted again once the ring has a free buffer; what is
    // pending is delivered meanwhile.
    if (!(flags & IORING_CQE_F_MORE) && !_has_terminal) {
        _event = nullptr;
        _starved = true;
        if (_free > 0 && !_resubmit()) {
            _has_terminal = true;
            _terminal_error = ENOBUFS;
        }
    }

    _wake_waiter();
}

void BufferRing::_wake_waiter() {
    if (_waiter) {
        rawio::RecvStream::Item out;
        int out_error = 0;
        if (try_produce(_waiter_want, out, out_error)) {
            auto h = std::exchange(_waiter, nullptr);
            if (!out_error) {
                *_waiter_item = std::move(out);
            }
            *_waiter_error = out_error;
            _waiter_item = nullptr;
            _waiter_error = nullptr;
            h.resume();
        }
    }
}

bool BufferRing::try_produce(
    size_t want, rawio::RecvStream::Item& out, int& error
) noexcept {
    if (want > 0 && _pending_size >= want) {
        _extract(want, out);
        error = 0;
        return true;
    }
    // Every buffer of the ring holds data that is not enough for `want`:
    // nothing can free one, so the stream cannot be refilled -- what is wanted
    // does not fit the ring.
    if (_starved && !_has_terminal && _free == 0 &&
        _pending_entries.size() == _entries && _pending_size < want) {
        _has_terminal = true;
        _terminal_error = ENOBUFS;
    }
    if (_has_terminal) {
        // Gated on `_size` (== `want` here) even while delivering a
        // terminal error: paused (want == 0) means nothing gets drained
        // even if data is sitting there -- the error is reported with an
        // empty item instead. Otherwise, drain whatever partial amount is
        // pending
        // (possibly all of it, possibly less than `want`) as one last
        // successful item; the error itself surfaces on the *next* call.
        size_t drain = std::min(_pending_size, want);
        if (drain > 0) {
            _extract(drain, out);
            error = 0;
            return true;
        }
        error = _terminal_error;
        return true;
    }
    return false;
}

void BufferRing::set_waiter(
    std::coroutine_handle<> h, size_t want, rawio::RecvStream::Item* out,
    int* error
) noexcept {
    _waiter = h;
    _waiter_want = want;
    _waiter_item = out;
    _waiter_error = error;
}

bool BufferRing::_resubmit() noexcept {
    try {
        _q.resubmit_recv_multishot(shared_from_this(), _fd, _flags);
    } catch (...) {
        return false;
    }
    _starved = false;
    return true;
}

void BufferRing::on_release() noexcept {
    ++_free;
    if (_starved && !_closed && !_has_terminal && !_resubmit()) {
        // Nothing is armed and nothing will release a buffer to try again:
        // a consumer that waits would wait for ever.
        _has_terminal = true;
        _terminal_error = ENOBUFS;
        _wake_waiter();
    }
}

void BufferRing::close() noexcept {
    _closed = true;
    if (_event != nullptr && !_has_terminal) {
        try {
            _q.cancel(_event);
        } catch (...) {
        }
    }
}

void BufferRing::cancel() noexcept {
    if (_has_terminal || _closed) {
        return;
    }
    _cancel_requested = true;
    try {
        if (_event != nullptr) {
            _q.cancel(_event);
        } else if (_starved) {
            if (_resubmit()) {
                // The registration that ends the stream: it completes with
                // the cancellation, or with ENOBUFS if the ring is still
                // empty.
                _q.cancel(_event);
            } else {
                _has_terminal = true;
                _terminal_error = ECANCELED;
                _wake_waiter();
            }
        }
    } catch (...) {
    }
}

} // namespace uring
} // namespace rawio
