#include "poll_event.hpp"

#include <rawstorio/task.hpp>

#include <rawstorstd/logging.h>
#include <rawstorstd/iovec.h>

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
    } catch (std::exception &e) {
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
        trace(
            __FILE__, __LINE__, __FUNCTION__, "completed");
#endif
        return ret;
    }

    _buf_at = static_cast<char*>(_buf_at) + shift;
    _result += shift;
    _size_at -= shift;
#ifdef RAWSTOR_TRACE_EVENTS
    trace(
        __FILE__, __LINE__, __FUNCTION__, "partial");
#endif
    return 0;
}


void EventMultiplexScalar::add_to_batch(std::vector<iovec> &iov) {
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
        trace(
            __FILE__, __LINE__, __FUNCTION__, "completed");
#endif
        return shift - _size_at;
    };

    rawstor_iovec_discard_front(&_iov_at, &_niov_at, shift);
    _result += shift;
    _size_at -= shift;
#ifdef RAWSTOR_TRACE_EVENTS
    trace(
        __FILE__, __LINE__, __FUNCTION__, "partial");
#endif
    return 0;
}


void EventMultiplexVector::add_to_batch(std::vector<iovec> &iov) {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "add to batch");
#endif
    for (unsigned int i = 0; i < _niov_at; ++i) {
        iov.push_back(_iov_at[i]);
    }
}


void EventMultiplexScalarRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "read()");
#endif
    ssize_t res = ::read(_t->fd(), _buf_at, _size_at);
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    shift(res);
}


void EventMultiplexVectorRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "readv()");
#endif
    ssize_t res = ::readv(_t->fd(), _iov_at, _niov_at);
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    shift(res);
}


void EventSimplexScalarPositionalRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "pread()");
#endif
    ssize_t res = ::pread(
        _t->fd(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->buf(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->size(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->offset());
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
    if (
        (size_t)_result ==
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->size())
    {
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
    } else {
        trace(__FILE__, __LINE__, __FUNCTION__, "partial");
    }
#endif
}


void EventSimplexVectorPositionalRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "preadv()");
#endif
    ssize_t res = ::preadv(
        _t->fd(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->iov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->niov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->offset()
    );
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
    if (
        (size_t)_result ==
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->size())
    {
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
    } else {
        trace(__FILE__, __LINE__, __FUNCTION__, "partial");
    }
#endif
}


void EventSimplexMessageRead::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "recvmsg()");
#endif
    ssize_t res = ::recvmsg(
        _t->fd(),
        static_cast<rawstor::io::TaskMessage*>(
            _t.get())->msg(),
        static_cast<rawstor::io::TaskMessage*>(
            _t.get())->flags()
    );
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
    if (
        (size_t)_result ==
        static_cast<rawstor::io::TaskMessage*>(
            _t.get())->size())
    {
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
    } else {
        trace(__FILE__, __LINE__, __FUNCTION__, "partial");
    }
#endif
}


void EventMultiplexScalarWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "write()");
#endif
    ssize_t res = ::write(_t->fd(), _buf_at, _size_at);
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    shift(res);
}


void EventMultiplexVectorWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "writev()");
#endif
    ssize_t res = ::writev(_t->fd(), _iov_at, _niov_at);
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    shift(res);
}


void EventSimplexScalarPositionalWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "pwrite()");
#endif
    ssize_t res = ::pwrite(
        _t->fd(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->buf(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->size(),
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->offset());
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
    if (
        (size_t)_result ==
        static_cast<rawstor::io::TaskScalarPositional*>(
            _t.get())->size())
    {
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
    } else {
        trace(__FILE__, __LINE__, __FUNCTION__, "partial");
    }
#endif
}


void EventSimplexVectorPositionalWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "pwritev()");
#endif
    ssize_t res = ::pwritev(
        _t->fd(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->iov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->niov(),
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->offset()
    );
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
    if (
        (size_t)_result ==
        static_cast<rawstor::io::TaskVectorPositional*>(
            _t.get())->size())
    {
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
    } else {
        trace(__FILE__, __LINE__, __FUNCTION__, "partial");
    }
#endif
}


void EventSimplexMessageWrite::process() noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "sendmsg()");
#endif
    ssize_t res = ::sendmsg(
        _t->fd(),
        static_cast<rawstor::io::TaskMessage*>(
            _t.get())->msg(),
        static_cast<rawstor::io::TaskMessage*>(
            _t.get())->flags()
    );
    if (res == -1) {
        int error = errno;
        errno = 0;
        set_error(error);
    }
    _result = res;
#ifdef RAWSTOR_TRACE_EVENTS
    if (
        (size_t)_result ==
        static_cast<rawstor::io::TaskMessage*>(
            _t.get())->size())
    {
        trace(__FILE__, __LINE__, __FUNCTION__, "completed");
    } else {
        trace(__FILE__, __LINE__, __FUNCTION__, "partial");
    }
#endif
}


}}} // rawstor::io::poll
