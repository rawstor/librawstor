#ifndef RAWIO_POLL_STREAM_BACKEND_HPP
#define RAWIO_POLL_STREAM_BACKEND_HPP

// Out-of-line definitions for SingleSlotStreamBackend<BackendBase, dedup>
// (declared in poll_event.hpp). Split out from poll_event.hpp because the
// method bodies need rawio::poll::Queue's complete type
// (cancel()/dispatch_generation()), and poll_event.hpp can only
// forward-declare Queue (poll_queue.hpp includes poll_event.hpp, not the
// other way around). Included from both poll_event.cpp (Event::dispatch()
// forwards into these) and poll_queue.cpp (Queue::poll_multishot()/
// accept_multishot() construct one), which both already include
// poll_queue.hpp.

#include "poll_event.hpp"
#include "poll_queue.hpp"

#include <algorithm>
#include <utility>

#include <cerrno>

namespace rawio {
namespace poll {

template <typename BackendBase, bool dedup>
SingleSlotStreamBackend<BackendBase, dedup>::SingleSlotStreamBackend(
    Queue& q, unsigned int last_generation
) :
    _q(q),
    _last_generation(last_generation),
    _waiter(),
    _waiter_out(nullptr),
    _waiter_error(nullptr),
    _has_pending(false),
    _pending_value(0),
    _pending_error(0),
    _pending_overflow(false),
    _closed(false),
    _terminated(false),
    _terminal_error(0),
    _event(nullptr) {
}

template <typename BackendBase, bool dedup>
bool SingleSlotStreamBackend<BackendBase, dedup>::try_produce(
    int& out, int& error
) noexcept {
    if (_has_pending) {
        out = _pending_value;
        error = _pending_error;
        bool was_error = _pending_error != 0;
        _has_pending = false;
        if (_pending_overflow && !was_error) {
            _terminated = true;
            _terminal_error = ENOBUFS;
        }
        return true;
    }
    if (_pending_overflow) {
        _pending_overflow = false;
        error = ENOBUFS;
        _terminated = true;
        _terminal_error = ENOBUFS;
        return true;
    }
    if (_terminated) {
        error = _terminal_error;
        return true;
    }
    return false;
}

template <typename BackendBase, bool dedup>
void SingleSlotStreamBackend<BackendBase, dedup>::set_waiter(
    std::coroutine_handle<> h, int* out, int* error
) noexcept {
    _waiter = h;
    _waiter_out = out;
    _waiter_error = error;
}

template <typename BackendBase, bool dedup>
void SingleSlotStreamBackend<BackendBase, dedup>::close() noexcept {
    _closed = true;
    if (_event != nullptr && !_terminated) {
        try {
            _q.cancel(_event);
        } catch (...) {
        }
    }
}

template <typename BackendBase, bool dedup>
void SingleSlotStreamBackend<BackendBase, dedup>::on_completion(
    int value, int error
) {
    if (_closed) {
        return;
    }
    if constexpr (dedup) {
        if (_last_generation == _q.dispatch_generation()) {
            // Same-batch duplicate wakeup, see poll::Queue's
            // _dispatch_generation doc comment.
            return;
        }
        _last_generation = _q.dispatch_generation();
    }

    if (_waiter) {
        auto h = std::exchange(_waiter, nullptr);
        *_waiter_out = value;
        *_waiter_error = error;
        _waiter_out = nullptr;
        _waiter_error = nullptr;
        if (error) {
            _terminated = true;
            _terminal_error = error;
        }
        h.resume();
        return;
    }

    if (_has_pending) {
        _pending_overflow = true;
        return;
    }

    if (error) {
        _terminated = true;
        _terminal_error = error;
    }
    _has_pending = true;
    _pending_value = value;
    _pending_error = error;
}

inline RecvMultishotBackend::RecvMultishotBackend(
    Queue& q, unsigned int entries
) :
    _q(q),
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
}

inline void
RecvMultishotBackend::_extract(size_t want, rawio::RecvStream::Item& out) {
    auto entries = std::make_shared<
        std::list<std::unique_ptr<EventSimplexVectorRecvMultishotEntry>>>();
    std::vector<iovec> iov;
    size_t iov_size = 0;
    iov.reserve(_pending_entries.size());

    while (!_pending_entries.empty() && want) {
        EventSimplexVectorRecvMultishotEntry& e = _pending_entries.tail();
        void* e_data = static_cast<char*>(e.data()) + _pending_offset;
        size_t e_size = e.result() - _pending_offset;
        if (e_size <= want - iov_size) {
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

inline bool RecvMultishotBackend::on_arrival(int error) {
    if (_closed) {
        return _has_terminal;
    }

    bool was_full = _pending_entries.full();

    if (error && !_has_terminal) {
        _has_terminal = true;
        _terminal_error = error;
    }
    if (was_full && !_has_terminal) {
        _has_terminal = true;
        _terminal_error = ENOBUFS;
    }

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

    return _has_terminal;
}

inline bool RecvMultishotBackend::try_produce(
    size_t want, rawio::RecvStream::Item& out, int& error
) noexcept {
    if (want > 0 && _pending_size >= want) {
        _extract(want, out);
        error = 0;
        return true;
    }
    if (_has_terminal) {
        // See uring::BufferRing::try_produce()'s doc comment for why this
        // is min(pending, want) rather than always draining everything
        // pending: paused (want == 0) must not drain anything even if
        // data is sitting there.
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

inline void RecvMultishotBackend::set_waiter(
    std::coroutine_handle<> h, size_t want, rawio::RecvStream::Item* out,
    int* error
) noexcept {
    _waiter = h;
    _waiter_want = want;
    _waiter_item = out;
    _waiter_error = error;
}

inline void RecvMultishotBackend::close() noexcept {
    _closed = true;
    if (_event != nullptr && !_has_terminal) {
        try {
            _q.cancel(_event);
        } catch (...) {
        }
    }
}

} // namespace poll
} // namespace rawio

#endif // RAWIO_POLL_STREAM_BACKEND_HPP
