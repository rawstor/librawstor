#ifndef RAWSTORIO_POLL_EVENT_HPP
#define RAWSTORIO_POLL_EVENT_HPP

#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <cstddef>
#include <cstdio>

namespace rawstor {
namespace io {
namespace poll {


class Queue;


class Event {
    protected:
        Queue &_q;
        std::unique_ptr<rawstor::io::Task> _t;
        ssize_t _result;
        int _error;

    public:
        Event(
            Queue &q,
            std::unique_ptr<rawstor::io::Task> t):
            _q(q),
            _t(std::move(t)),
            _result(0),
            _error(0)
        {}

        virtual ~Event() {}

        inline void set_error(int error) noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
            trace(__FILE__, __LINE__, __FUNCTION__, "error");
#endif
            _error = error;
        }

        void dispatch() {
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

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(
            const char *file, int line, const char *function,
            const std::string &message)
        {
            _t->trace(file, line, function, message);
        }
#endif
        virtual bool multiplex() const noexcept = 0;

        virtual void process() noexcept = 0;
};


class EventSimplex: public Event {
    public:
        EventSimplex(
            Queue &q,
            std::unique_ptr<rawstor::io::Task> t):
            Event(q, std::move(t))
        {}

        virtual ~EventSimplex() {}

        bool multiplex() const noexcept override final {
            return false;
        };
};


class EventMultiplex: public Event {
    public:
        EventMultiplex(
            Queue &q,
            std::unique_ptr<rawstor::io::Task> t):
            Event(q, std::move(t))
        {}

        virtual ~EventMultiplex() {}

        bool multiplex() const noexcept override final {
            return true;
        };

        virtual unsigned int niov() const noexcept = 0;

        virtual bool completed() const noexcept = 0;

        virtual size_t shift(size_t shift) noexcept = 0;

        virtual void add_to_batch(std::vector<iovec> &iov) = 0;
};


class EventMultiplexScalar: public EventMultiplex {
    protected:
        void *_buf_at;
        size_t _size_at;

    public:
        EventMultiplexScalar(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskScalar> t):
            EventMultiplex(q, std::move(t)),
            _buf_at(static_cast<rawstor::io::TaskScalar*>(_t.get())->buf()),
            _size_at(static_cast<rawstor::io::TaskScalar*>(_t.get())->size())
        {}

        virtual ~EventMultiplexScalar() {}

        unsigned int niov() const noexcept override final {
            return 1;
        }

        bool completed() const noexcept override final {
            return _size_at == 0;
        }

        size_t shift(size_t shift) noexcept override final {
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

        void add_to_batch(std::vector<iovec> &iov) override final {
#ifdef RAWSTOR_TRACE_EVENTS
            trace(__FILE__, __LINE__, __FUNCTION__, "add to batch");
#endif
            iov.push_back((iovec){
                .iov_base = _buf_at,
                .iov_len = _size_at,
            });
        }
};


class EventMultiplexVector: public EventMultiplex {
    protected:
        std::vector<iovec> _iov;
        iovec *_iov_at;
        unsigned int _niov_at;
        size_t _size_at;

    public:
        EventMultiplexVector(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskVector> t):
            EventMultiplex(q, std::move(t)),
            _niov_at(static_cast<rawstor::io::TaskVector*>(_t.get())->niov()),
            _size_at(static_cast<rawstor::io::TaskVector*>(_t.get())->size())
        {
            iovec *iov = static_cast<rawstor::io::TaskVector*>(_t.get())->iov();
            _iov.reserve(_niov_at);
            for (unsigned int i = 0; i < _niov_at; ++i) {
                _iov.push_back(iov[i]);
            }
            _iov_at = _iov.data();
        }

        virtual ~EventMultiplexVector() {}

        unsigned int niov() const noexcept override final {
            return _niov_at;
        }

        bool completed() const noexcept override final {
            return _niov_at == 0;
        }

        size_t shift(size_t shift) noexcept override final {
            if (shift >= _size_at) {
                _result += _size_at;
                _niov_at = 0;
#ifdef RAWSTOR_TRACE_EVENTS
                trace(
                    __FILE__, __LINE__, __FUNCTION__, "completed");
#endif
                return shift - _size_at;
            };

            rawstor_iovec_shift(&_iov_at, &_niov_at, shift);
            _result += shift;
            _size_at -= shift;
#ifdef RAWSTOR_TRACE_EVENTS
            trace(
                __FILE__, __LINE__, __FUNCTION__, "partial");
#endif
            return 0;
        }

        void add_to_batch(std::vector<iovec> &iov) override final {
#ifdef RAWSTOR_TRACE_EVENTS
            trace(__FILE__, __LINE__, __FUNCTION__, "add to batch");
#endif
            for (unsigned int i = 0; i < _niov_at; ++i) {
                iov.push_back(_iov_at[i]);
            }
        }
};


class EventMultiplexScalarRead final: public EventMultiplexScalar {
    public:
        EventMultiplexScalarRead(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskScalar> t):
            EventMultiplexScalar(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventMultiplexVectorRead final: public EventMultiplexVector {
    public:
        EventMultiplexVectorRead(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskVector> t):
            EventMultiplexVector(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventSimplexScalarPositionalRead final: public EventSimplex {
    public:
        EventSimplexScalarPositionalRead(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskScalarPositional> t):
            EventSimplex(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventSimplexVectorPositionalRead final: public EventSimplex {
    public:
        EventSimplexVectorPositionalRead(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskVectorPositional> t):
            EventSimplex(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventSimplexMessageRead final: public EventSimplex {
    public:
        EventSimplexMessageRead(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskMessage> t):
            EventSimplex(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventMultiplexScalarWrite final: public EventMultiplexScalar {
    public:
        EventMultiplexScalarWrite(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskScalar> t):
            EventMultiplexScalar(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventMultiplexVectorWrite final: public EventMultiplexVector {
    public:
        EventMultiplexVectorWrite(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskVector> t):
            EventMultiplexVector(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventSimplexScalarPositionalWrite final: public EventSimplex {
    public:
        EventSimplexScalarPositionalWrite(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskScalarPositional> t):
            EventSimplex(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventSimplexVectorPositionalWrite final: public EventSimplex {
    public:
        EventSimplexVectorPositionalWrite(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskVectorPositional> t):
            EventSimplex(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


class EventSimplexMessageWrite final: public EventSimplex {
    public:
        EventSimplexMessageWrite(
            Queue &q,
            std::unique_ptr<rawstor::io::TaskMessage> t):
            EventSimplex(q, std::move(t))
        {}

        void process() noexcept override final {
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
};


}}} // rawstor::io


#endif // RAWSTORIO_POLL_EVENT_HPP
