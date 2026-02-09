#include "poll_event.hpp"

#include <rawstorio/task.hpp>

#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>

#include <sstream>
#include <vector>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {
namespace poll {

void Event::dispatch() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "callback");
    try {
#endif
        (*_t)(_result, _error);
#ifdef RAWSTOR_TRACE_EVENTS
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "callback error: " << e.what();
        trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
        throw;
    }
    trace(__FILE__, __LINE__, __FUNCTION__, "callback success");
#endif
}

size_t EventMultiplexScalar::shift(size_t shift) noexcept {
    if (shift >= _size_at) {
        size_t ret = shift - _size_at;
        _result += _size_at;
        _size_at = 0;
#ifdef RAWSTOR_TRACE_EVENTS
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
#endif
        return ret;
    }

    _buf_at = static_cast<const char*>(_buf_at) + shift;
    _result += shift;
    _size_at -= shift;
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "partial");
#endif
    return 0;
}

void EventMultiplexScalar::add_to_batch(std::vector<iovec>& iov) {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "add to batch");
#endif
    iov.push_back((iovec){
        .iov_base = const_cast<void*>(_buf_at),
        .iov_len = _size_at,
    });
}

size_t EventMultiplexVector::shift(size_t shift) noexcept {
    if (shift >= _size_at) {
        _result += _size_at;
        _niov_at = 0;
#ifdef RAWSTOR_TRACE_EVENTS
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
#endif
        return shift - _size_at;
    };

    rawstor_iovec_discard_front(&_iov_at, &_niov_at, shift);
    _result += shift;
    _size_at -= shift;
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "partial");
#endif
    return 0;
}

void EventMultiplexVector::add_to_batch(std::vector<iovec>& iov) {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "add to batch");
#endif
    for (unsigned int i = 0; i < _niov_at; ++i) {
        iov.push_back(_iov_at[i]);
    }
}

ssize_t EventSimplexPoll::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "process()");
#endif
    return 0;
}

void EventSimplexPollMultishot::dispatch() {
    Event::dispatch();
    _result = 0;
}

ssize_t EventSimplexScalarRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "read()");
#endif
    ssize_t res = ::read(_fd, _buf, _size);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == _size) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexVectorRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "readv()");
#endif
    ssize_t res = ::readv(_fd, _iov, _niov);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == rawstor_iovec_size(_iov, _niov)) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexScalarPositionalRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "pread()");
#endif
    ssize_t res = ::pread(_fd, _buf, _size, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == _size) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexVectorPositionalRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "preadv()");
#endif
    ssize_t res = ::preadv(_fd, _iov, _niov, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == rawstor_iovec_size(_iov, _niov)) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexScalarRecv::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "recv()");
#endif
    ssize_t res = ::recv(_fd, _buf, _size, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == _size) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
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
    return _pending_size >=
           static_cast<rawstor::io::TaskVectorExternal*>(_t.get())->size();
}

ssize_t EventSimplexVectorRecvMultishot::process() noexcept {
    ssize_t res = -ENOBUFS;

    while (!_pending_entries.full()) {
#ifdef RAWSTOR_TRACE_EVENTS
        trace(__FILE__, __LINE__, __FUNCTION__, "recv()");
#endif
        std::unique_ptr<EventSimplexVectorRecvMultishotEntry> entry =
            std::make_unique<EventSimplexVectorRecvMultishotEntry>(_entry_size);
        res = ::recv(_fd, entry->data(), entry->size(), _flags);

        if (res >= 0) {
            entry->set_result(res);
            _pending_size += res;
            _pending_entries.push(std::move(entry));

#ifdef RAWSTOR_TRACE_EVENTS
            if (_pending_size >=
                static_cast<rawstor::io::TaskVectorExternal*>(_t.get())
                    ->size()) {
                trace(__FILE__, __LINE__, __FUNCTION__, "completed");
            } else {
                trace(__FILE__, __LINE__, __FUNCTION__, "partial");
            }
#endif
        } else {
            int error = errno;
            errno = 0;
            if (error != EAGAIN) {
                set_error(error);
            }
#ifdef RAWSTOR_TRACE_EVENTS
            if (error == EAGAIN) {
                trace(__FILE__, __LINE__, __FUNCTION__, "received all");
            }
#endif
            break;
        }
    }

    return res;
}

void EventSimplexVectorRecvMultishot::dispatch() {
    bool full = _pending_entries.full();

    TaskVectorExternal* t = static_cast<TaskVectorExternal*>(_t.get());
    while (_pending_size >= t->size() || _error) {
        std::list<std::unique_ptr<EventSimplexVectorRecvMultishotEntry>>
            entries;
        std::vector<iovec> iov;
        size_t iov_size = 0;
        iov.reserve(_pending_entries.size());

        while (!_pending_entries.empty()) {
            EventSimplexVectorRecvMultishotEntry& e = _pending_entries.tail();
            void* e_data = static_cast<char*>(e.data()) + _pending_offset;
            size_t e_size = e.result() - _pending_offset;
            if (e_size <= t->size() - iov_size) [[likely]] {
                iov.push_back({.iov_base = e_data, .iov_len = e_size});
                _pending_offset = 0;
                _pending_size -= e_size;
                entries.push_back(_pending_entries.pop());
                iov_size += e_size;
                if (iov_size == t->size()) {
                    break;
                }
            } else {
                iov.push_back(
                    {.iov_base = e_data, .iov_len = t->size() - iov_size}
                );
                _pending_offset += iov.back().iov_len;
                _pending_size -= iov.back().iov_len;
                iov_size += iov.back().iov_len;
                break;
            }
        }

        _result = iov_size;
        t->set(iov.data(), iov.size());
        try {
#ifdef RAWSTOR_TRACE_EVENTS
            std::ostringstream oss;
            oss << "sending iov: niov = " << iov.size()
                << ", size = " << iov_size;
            t->trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
            Event::dispatch();
        } catch (...) {
            t->set(nullptr, 0);
            throw;
        }
        t->set(nullptr, 0);

        if (_error) {
            break;
        }
    }

    if (full && !_error) {
        t->set(nullptr, 0);
        _result = 0;
        set_error(ENOBUFS);
        Event::dispatch();
    }
}

ssize_t EventSimplexMessageRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "recvmsg()");
#endif
    ssize_t res = ::recvmsg(_fd, _msg, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            rawstor_iovec_size(_msg->msg_iov, _msg->msg_iovlen)) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
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
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "write()");
#endif
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
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "writev()");
#endif
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

ssize_t EventSimplexScalarPositionalWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "pwrite()");
#endif
    ssize_t res = ::pwrite(_fd, _buf, _size, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == _size) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexVectorPositionalWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "pwritev()");
#endif
    ssize_t res = ::pwritev(_fd, _iov, _niov, _offset);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == rawstor_iovec_size(_iov, _niov)) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexScalarSend::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "send()");
#endif
    ssize_t res = ::send(_fd, _buf, _size, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result == _size) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    return res;
}

ssize_t EventSimplexMessageWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "sendmsg()");
#endif
    ssize_t res = ::sendmsg(_fd, _msg, _flags);
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            rawstor_iovec_size(_msg->msg_iov, _msg->msg_iovlen)) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
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
} // namespace io
} // namespace rawstor
