#include "uring_event.hpp"

#include "uring_queue.hpp"

#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>

#include <liburing.h>

#include <sstream>

namespace rawstor {
namespace io {
namespace uring {

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

void EventPoll::set_result(ssize_t res) noexcept {
    if (res >= 0) {
        _result = res;
    } else {
        _error = -res;
#ifdef RAWSTOR_TRACE_EVENTS
        std::ostringstream oss;
        oss << "error " << _error;
        trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
    }
}

void EventPoll::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_poll_add()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_poll_add(
        sqe, _t->fd(), static_cast<rawstor::io::TaskPoll*>(_t.get())->mask()
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventScalar::set_result(ssize_t res) noexcept {
    if (res >= 0) {
        _buf_at = static_cast<char*>(_buf_at) + res;
        _size_at -= res;
        _result += res;
#ifdef RAWSTOR_TRACE_EVENTS
        if (_size_at == 0) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        _error = -res;
#ifdef RAWSTOR_TRACE_EVENTS
        std::ostringstream oss;
        oss << "error " << _error;
        trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
    }
}

void EventVector::set_result(ssize_t res) noexcept {
    if (res >= 0) {
        rawstor_iovec_discard_front(&_iov_at, &_niov_at, res);
        _size_at -= res;
        _result += res;
#ifdef RAWSTOR_TRACE_EVENTS
        if (_size_at == 0) {
            trace(__FILE__, __LINE__, __FUNCTION__, "completed");
        } else {
            trace(__FILE__, __LINE__, __FUNCTION__, "partial");
        }
#endif
    } else {
        _error = -res;
#ifdef RAWSTOR_TRACE_EVENTS
        std::ostringstream oss;
        oss << "error " << _error;
        trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
    }
}

void EventScalarRead::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_read()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_read(sqe, _t->fd(), _buf_at, _size_at, 0);
    io_uring_sqe_set_data(sqe, this);
}

void EventVectorRead::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_readv()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_readv(
        sqe, _t->fd(), static_cast<rawstor::io::TaskVector*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(_t.get())->niov(), 0
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventScalarPositionalRead::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_read()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_read(
        sqe, _t->fd(),
        static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->size(),
        static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->offset()
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventVectorPositionalRead::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_readv()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_readv(
        sqe, _t->fd(),
        static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->niov(),
        static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->offset()
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventMessageRead::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_recvmsg()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_recvmsg(
        sqe, _t->fd(), static_cast<rawstor::io::TaskMessage*>(_t.get())->msg(),
        static_cast<rawstor::io::TaskMessage*>(_t.get())->flags()
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventScalarWrite::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_write()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_write(sqe, _t->fd(), _buf_at, _size_at, 0);
    io_uring_sqe_set_data(sqe, this);
}

void EventVectorWrite::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_writev()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_writev(
        sqe, _t->fd(), static_cast<rawstor::io::TaskVector*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVector*>(_t.get())->niov(), 0
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventScalarPositionalWrite::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_write()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_write(
        sqe, _t->fd(),
        static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->buf(),
        static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->size(),
        static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->offset()
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventVectorPositionalWrite::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_writev()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_writev(
        sqe, _t->fd(),
        static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->iov(),
        static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->niov(),
        static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->offset()
    );
    io_uring_sqe_set_data(sqe, this);
}

void EventMessageWrite::prep() {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "io_uring_prep_sendmsg()");
#endif
    io_uring_sqe* sqe = _q.get_sqe();
    io_uring_prep_sendmsg(
        sqe, _t->fd(), static_cast<rawstor::io::TaskMessage*>(_t.get())->msg(),
        static_cast<rawstor::io::TaskMessage*>(_t.get())->flags()
    );
    io_uring_sqe_set_data(sqe, this);
}

} // namespace uring
} // namespace io
} // namespace rawstor
