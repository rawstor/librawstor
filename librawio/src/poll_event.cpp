#include "poll_event.hpp"

#include "poll_queue.hpp"
#include "poll_stream_backend.hpp"

#include <rawstd/gcc.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <system_error>
#include <utility>
#include <vector>

#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

namespace rawio {
namespace poll {

void EventEval::dispatch() {
    if (_on_dispatch) {
        _on_dispatch(*this);
    } else {
        resolve_one_shot_raw(_result);
    }
}

ssize_t EventEval::process() noexcept {
    _result = _eval();
    return _result;
}

void EventSimplex::dispatch() {
    if (_on_dispatch) {
        _on_dispatch(*this);
    } else {
        resolve_one_shot();
    }
}

void EventMultiplex::dispatch() {
    if (_on_dispatch) {
        _on_dispatch(*this);
    } else {
        resolve_one_shot();
    }
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

void EventSimplexPollMultishot::dispatch() {
    if (_error) {
        _backend->on_completion(0, _error);
    } else {
        _backend->on_completion(static_cast<int>(_result), 0);
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
    if (_error) {
        _backend->on_completion(0, _error);
    } else {
        _backend->on_completion(static_cast<int>(_result), 0);
    }
    _result = 0;
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

void EventSimplexVectorRecvMultishot::dispatch() {
    bool terminal = _backend->on_arrival(_error);
    if (terminal && !_error) {
        // The backend reached a terminal condition on its own (the
        // provided-buffer pool running dry, detected independently of
        // whatever `process()` saw) -- reflect that on the Event itself
        // too, so _wait_timeout()'s "stop re-arming a multishot event
        // once it has errored" check actually stops re-arming this one
        // (matches cancel() throwing ENOENT afterwards, since the event
        // is gone rather than still live and re-armed).
        set_error(ENOBUFS);
    }
}

ssize_t EventSimplexVectorRecvMultishot::process() noexcept {
    ssize_t res = -ENOBUFS;

    while (!_backend->full()) {
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "recv()");
        std::unique_ptr<EventSimplexVectorRecvMultishotEntry> entry =
            std::make_unique<EventSimplexVectorRecvMultishotEntry>(_entry_size);
        res = ::recv(_fd, entry->data(), entry->size(), _flags);

        if (res > 0) {
            entry->set_result(res);
            RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "partial");
            _backend->add_entry(std::move(entry));
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

ssize_t EventSimplexScalarPositionalWrite::process() noexcept {
#if defined(RAWSTD_ON_LINUX)
    ssize_t res;
    if (_sync) {
        // There is no scalar pwrite2(2) syscall on Linux, only the vectored
        // preadv2/pwritev2 family -- wrap the buffer in a single-element
        // iovec to reach RWF_DSYNC. Only worth the vectored-I/O overhead
        // (import_iovec() on every call) when a flag actually needs it;
        // plain pwrite() below is cheaper for the common non-sync case.
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwritev2()");
        iovec iov{.iov_base = const_cast<void*>(_buf), .iov_len = _size};
        res = ::pwritev2(_fd, &iov, 1, _offset, RWF_DSYNC);
    } else {
        RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwrite()");
        res = ::pwrite(_fd, _buf, _size, _offset);
    }
#elif defined(RAWSTD_ON_MACOS)
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwrite()");
    ssize_t res = ::pwrite(_fd, _buf, _size, _offset);
    if (res >= 0 && _sync && ::fcntl(_fd, F_FULLFSYNC) == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
        return -1;
    }
#else
#error "Unexpected platform"
#endif
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

ssize_t EventSimplexVectorPositionalWrite::process() noexcept {
#if defined(RAWSTD_ON_LINUX)
    // Unlike the scalar case, no branching needed here: the kernel routes
    // pwritev(2) and pwritev2(2) through the same import_iovec()+vectored
    // write path regardless, so pwritev2(..., 0) costs nothing extra over
    // pwritev() -- this call was already paying that cost either way.
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwritev2()");
    ssize_t res = ::pwritev2(_fd, _iov, _niov, _offset, _sync ? RWF_DSYNC : 0);
#elif defined(RAWSTD_ON_MACOS)
    RAWSTD_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "pwritev()");
    ssize_t res = ::pwritev(_fd, _iov, _niov, _offset);
    if (res >= 0 && _sync && ::fcntl(_fd, F_FULLFSYNC) == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
        return -1;
    }
#else
#error "Unexpected platform"
#endif
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
