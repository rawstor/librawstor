#include "poll_event.hpp"

#include "poll_queue.hpp"

#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <system_error>
#include <utility>
#include <vector>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace {

template <typename T, typename... Args>
inline void
dispatch(const rawstd::TraceEvent& trace_event, T&& cb, Args&&... args) {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "callback");
#ifdef RAWSTD_TRACE_EVENTS
    try {
#endif
        std::forward<T>(cb)(std::forward<Args>(args)...);
#ifdef RAWSTD_TRACE_EVENTS
    } catch (const std::exception& e) {
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "callback error: %s\n", e.what()
        );
        throw;
    }
#endif
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "callback success");
}

} // unnamed namespace

namespace rawio {
namespace poll {

void EventEval::dispatch() {
    ::dispatch(trace_event, _cb, _result);
}

ssize_t EventEval::process() noexcept {
    _result = _eval();
    return _result;
}

void EventMultiplex::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

size_t EventMultiplexScalar::shift(size_t shift) noexcept {
    if (shift >= _size_at) {
        size_t ret = shift - _size_at;
        _result += _size_at;
        _size_at = 0;
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        return ret;
    }

    _buf_at = static_cast<const char*>(_buf_at) + shift;
    _result += shift;
    _size_at -= shift;
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
    return 0;
}

void EventMultiplexScalar::add_to_batch(std::vector<iovec>& iov) {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "add to batch");
    iov.push_back((iovec){
        .iov_base = const_cast<void*>(_buf_at),
        .iov_len = _size_at,
    });
}

size_t EventMultiplexVector::shift(size_t shift) noexcept {
    if (shift >= _size_at) {
        _result += _size_at;
        _niov_at = 0;
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        return shift - _size_at;
    };

    rawstd_iovec_discard_front(&_iov_at, &_niov_at, shift);
    _result += shift;
    _size_at -= shift;
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
    return 0;
}

void EventMultiplexVector::add_to_batch(std::vector<iovec>& iov) {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "add to batch");
    for (unsigned int i = 0; i < _niov_at; ++i) {
        iov.push_back(_iov_at[i]);
    }
}

ssize_t EventSimplexPoll::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "process()");
    return 0;
}

void EventSimplexPollOneshot::dispatch() {
    if (!_error) {
        ::dispatch(trace_event, _cb, _result);
    } else {
        ::dispatch(trace_event, _cb, -_error);
    }
}

void EventSimplexPollMultishot::dispatch() {
    if (!_error) {
        ::dispatch(trace_event, _cb, _result);
    } else {
        ::dispatch(trace_event, _cb, -_error);
    }
    _result = 0;
}

ssize_t EventSimplexAcceptOneshot::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "accept()");
    ssize_t res = ::accept(_fd, _addr, _addrlen);
    if (res >= 0) {
        try {
            rawio::poll::Queue::setup_fd(res);
            _result = res;
#ifdef RAWSTD_TRACE_EVENTS
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
#endif
        } catch (const std::system_error& e) {
            rawstd_error("Failed to setup fd %zd: %s\n", res, e.what());
            ::close(res);
            res = -e.code().value();
            set_error(e.code().value());
        } catch (const std::exception& e) {
            rawstd_error("Failed to setup fd %zd: %s\n", res, e.what());
            ::close(res);
            res = -EIO;
            set_error(EIO);
        } catch (...) {
            rawstd_error("Failed to setup fd %zd\n", res);
            ::close(res);
            res = -EIO;
            set_error(EIO);
        }
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexAcceptOneshot::dispatch() {
    if (!_error) {
        ::dispatch(trace_event, _cb, _result);
    } else {
        ::dispatch(trace_event, _cb, -_error);
    }
}

ssize_t EventSimplexAcceptMultishot::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "accept()");
    ssize_t res = ::accept(_fd, nullptr, nullptr);
    if (res >= 0) {
        try {
            rawio::poll::Queue::setup_fd(res);
            _result = res;
#ifdef RAWSTD_TRACE_EVENTS
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
#endif
        } catch (const std::system_error& e) {
            rawstd_error("Failed to setup fd %zd: %s\n", res, e.what());
            ::close(res);
            res = -e.code().value();
            set_error(e.code().value());
        } catch (const std::exception& e) {
            rawstd_error("Failed to setup fd %zd: %s\n", res, e.what());
            ::close(res);
            res = -EIO;
            set_error(EIO);
        } catch (...) {
            rawstd_error("Failed to setup fd %zd\n", res);
            ::close(res);
            res = -EIO;
            set_error(EIO);
        }
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexAcceptMultishot::dispatch() {
    if (!_error) {
        ::dispatch(trace_event, _cb, _result);
    } else {
        ::dispatch(trace_event, _cb, -_error);
    }
    _result = 0;
}

void EventSimplexScalarRead::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexScalarRead::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "read()");
    ssize_t res = ::read(_fd, _buf, _size);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == _size) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexVectorRead::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexVectorRead::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "readv()");
    ssize_t res = ::readv(_fd, _iov, _niov);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == rawstd_iovec_size(_iov, _niov)) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexScalarPositionalRead::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexScalarPositionalRead::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pread()");
    ssize_t res = ::pread(_fd, _buf, _size, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == _size) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexVectorPositionalRead::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexVectorPositionalRead::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "preadv()");
    ssize_t res = ::preadv(_fd, _iov, _niov, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == rawstd_iovec_size(_iov, _niov)) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexScalarRecv::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexScalarRecv::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "recv()");
    ssize_t res = ::recv(_fd, _buf, _size, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == _size) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

bool EventSimplexVectorRecvMultishot::is_completed() const noexcept {
    return _pending_size >= _size;
}

void EventSimplexVectorRecvMultishot::dispatch() {
    bool full = _pending_entries.full();

    while (_pending_size >= _size || _error) {
        std::list<std::unique_ptr<EventSimplexVectorRecvMultishotEntry>>
            entries;
        std::vector<iovec> iov;
        size_t iov_size = 0;
        iov.reserve(_pending_entries.size());

        while (!_pending_entries.empty() && _size) {
            EventSimplexVectorRecvMultishotEntry& e = _pending_entries.tail();
            void* e_data = static_cast<char*>(e.data()) + _pending_offset;
            size_t e_size = e.result() - _pending_offset;
            if (e_size <= _size - iov_size) [[likely]] {
                iov.push_back({.iov_base = e_data, .iov_len = e_size});
                _pending_offset = 0;
                _pending_size -= e_size;
                entries.push_back(_pending_entries.pop());
                iov_size += e_size;
                if (iov_size == _size) {
                    break;
                }
            } else {
                iov.push_back(
                    {.iov_base = e_data, .iov_len = _size - iov_size}
                );
                _pending_offset += iov.back().iov_len;
                _pending_size -= iov.back().iov_len;
                iov_size += iov.back().iov_len;
                break;
            }
        }

        if (!_size && !_error) {
            break;
        }

        _result = iov_size;
        try {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event,
                "sending iov: niov = %zu, size = %zu, error = %d\n", iov.size(),
                iov_size, _error
            );
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "callback");
            int report_error = (iov_size < _size || !_size) ? _error : 0;
            _size = _cb(iov.data(), iov.size(), _result, report_error);
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "callback success");
            if (report_error) {
                break;
            }
        } catch (const std::exception& e) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "callback error: %s\n", e.what()
            );
            throw;
        }
    }

    if (full && !_error) {
        _result = 0;
        set_error(ENOBUFS);
        try {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "sending iov: niov = %u, size = %u\n", 0, 0
            );
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "callback");
            _size = _cb(nullptr, 0, _result, _error);
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "callback success");
        } catch (const std::exception& e) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "callback error: %s\n", e.what()
            );
            throw;
        }
    }
}

ssize_t EventSimplexVectorRecvMultishot::process() noexcept {
    ssize_t res = -ENOBUFS;

    while (!_pending_entries.full()) {
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "recv()");
        std::unique_ptr<EventSimplexVectorRecvMultishotEntry> entry =
            std::make_unique<EventSimplexVectorRecvMultishotEntry>(_entry_size);
        res = ::recv(_fd, entry->data(), entry->size(), _flags);

        if (res > 0) {
            entry->set_result(res);
            _pending_size += res;
            _pending_entries.push(std::move(entry));

#ifdef RAWSTD_TRACE_EVENTS
            if (_pending_size >= _size) {
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
            } else {
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
            }
#endif
        } else if (res == 0) {
            set_error(EPIPE);
            break;
        } else {
            int error = errno;
            errno = 0;
            if (error != EAGAIN) {
                set_error(error);
            }
#ifdef RAWSTD_TRACE_EVENTS
            if (error == EAGAIN) {
                RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "received all");
            }
#endif
            break;
        }
    }

    return res;
}

void EventSimplexMessageRead::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexMessageRead::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "recvmsg()");
    ssize_t res = ::recvmsg(_fd, _msg, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result ==
            rawstd_iovec_size(_msg->msg_iov, _msg->msg_iovlen)) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventMultiplexScalarWrite::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "write()");
    ssize_t res = ::write(_fd, _buf_at, _size_at);
    if (res >= 0) {
        shift(res);
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventMultiplexVectorWrite::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "writev()");
    ssize_t res = ::writev(_fd, _iov_at, _niov_at);
    if (res >= 0) {
        shift(res);
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexScalarPositionalWrite::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexScalarPositionalWrite::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwrite()");
    ssize_t res = ::pwrite(_fd, _buf, _size, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == _size) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexVectorPositionalWrite::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexVectorPositionalWrite::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwritev()");
    ssize_t res = ::pwritev(_fd, _iov, _niov, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == rawstd_iovec_size(_iov, _niov)) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexScalarSend::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexScalarSend::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "send()");
    ssize_t res = ::send(_fd, _buf, _size, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result == _size) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

void EventSimplexMessageWrite::dispatch() {
    ::dispatch(trace_event, _cb, _result, _error);
}

ssize_t EventSimplexMessageWrite::process() noexcept {
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "sendmsg()");
    ssize_t res = ::sendmsg(_fd, _msg, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTD_TRACE_EVENTS
        if ((size_t)_result ==
            rawstd_iovec_size(_msg->msg_iov, _msg->msg_iovlen)) {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "completed");
        } else {
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

} // namespace poll
} // namespace rawio
