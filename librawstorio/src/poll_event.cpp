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

    _buf_at = static_cast<char*>(_buf_at) + shift;
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
        .iov_base = _buf_at,
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

ssize_t EventSimplexScalarRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "read()");
#endif
    ssize_t res = ::read(
        _fd, static_cast<rawstor::io::TaskScalar*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(_t.get())->size()
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {
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
    ssize_t res = ::readv(
        _fd, static_cast<rawstor::io::TaskVector*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(_t.get())->niov()
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskVector*>(_t.get())->size()) {
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
    ssize_t res = ::pread(
        _fd, static_cast<rawstor::io::TaskScalar*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(_t.get())->size(), _offset
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {
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
    ssize_t res = ::preadv(
        _fd, static_cast<rawstor::io::TaskVector*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(_t.get())->niov(), _offset
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskVector*>(_t.get())->size()) {
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
    ssize_t res = ::recv(
        _fd, static_cast<rawstor::io::TaskScalar*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(_t.get())->size(), _flags
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {
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

ssize_t EventSimplexVectorRecvMultishot::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "recv()");
#endif
    (void)(_flags);
    ssize_t res = -1;
    errno = ECANCELED;
    // ssize_t res = ::recv(
    //     _fd, static_cast<rawstor::io::TaskSc,
    //     static_cast<rawstor::io::TaskScalar*>(_t.get())->size(), _flags
    // );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {
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

ssize_t EventSimplexMessageRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "recvmsg()");
#endif
    ssize_t res = ::recvmsg(
        _fd, static_cast<rawstor::io::TaskMessage*>(_t.get())->msg(), _flags
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskMessage*>(_t.get())->size()) {
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
    ssize_t res = ::pwrite(
        _fd, static_cast<rawstor::io::TaskScalar*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(_t.get())->size(), _offset
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {
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
    ssize_t res = ::pwritev(
        _fd, static_cast<rawstor::io::TaskVector*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(_t.get())->niov(), _offset
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskVector*>(_t.get())->size()) {
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
    ssize_t res = ::send(
        _fd, static_cast<rawstor::io::TaskScalar*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalar*>(_t.get())->size(), _flags
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {
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
    ssize_t res = ::sendmsg(
        _fd, static_cast<rawstor::io::TaskMessage*>(_t.get())->msg(), _flags
    );
    if (res >= 0) {
        _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
        if ((size_t)_result ==
            static_cast<rawstor::io::TaskMessage*>(_t.get())->size()) {
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
