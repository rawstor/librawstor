#ifndef RAWSTORIO_POLL_EVENT_HPP
#define RAWSTORIO_POLL_EVENT_HPP

#include "poll_queue.hpp"

#include <rawstorio/event.hpp>

#include <rawstorstd/logging.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

#include <vector>

#include <cstddef>
#include <cstdio>

namespace rawstor {
namespace io {
namespace poll {


class Event: public rawstor::io::Event {
    protected:
        std::vector<iovec> _iov;
        iovec *_iov_at;
        unsigned int _niov_at;
        ssize_t _result;
        int _error;

    public:
        Event(
            Queue &q, int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data):
            rawstor::io::Event(q, fd, size, cb, data),
            _iov(1, (iovec){.iov_base = buf, .iov_len = size}),
            _iov_at(_iov.data()),
            _niov_at(1),
            _result(0),
            _error(0)
        {}

        Event(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data):
            rawstor::io::Event(q, fd, size, cb, data),
            _niov_at(niov),
            _result(0),
            _error(0)
        {
            _iov.reserve(niov);
            for (unsigned int i = 0; i < niov; ++i) {
                _iov.push_back(iov[i]);
            }
            _iov_at = _iov.data();
        }

        virtual ~Event() {}

#ifdef RAWSTOR_TRACE_EVENTS
        virtual void trace(const std::string &message) = 0;
#endif

        inline size_t result() const noexcept {
            return _result;
        }

        inline int error() const noexcept {
            return _error;
        }

        inline virtual void set_error(int error) noexcept {
            _error = error;
        }

        inline iovec* iov() const noexcept {
            return _iov_at;
        }

        inline unsigned int niov() const noexcept {
            return _niov_at;
        }

        inline bool completed() const noexcept {
            return _niov_at == 0;
        }

        void add_iov(std::vector<iovec> &iov);

        virtual size_t shift(size_t shift);
};


class EventP: public Event {
    protected:
        off_t _offset;

    public:
        EventP(
            Queue &q, int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data):
            Event(q, fd, buf, size, cb, data),
            _offset(offset)
        {}

        EventP(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data):
            Event(q, fd, iov, niov, size, cb, data),
            _offset(offset)
        {}

        inline off_t offset() const noexcept {
            return _offset;
        }

        size_t shift(size_t shift);
};


class EventReadV: public Event {
    private:
#ifdef RAWSTOR_TRACE_EVENTS
        void *_trace_id;
#endif

    public:
        EventReadV(
            Queue &q, int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data):
            Event(q, fd, buf, size, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "read(%d, %zu)\n", fd, size))
#endif
        {}

        EventReadV(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data):
            Event(q, fd, iov, niov, size, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "readv(%d, %zu)\n", fd, size))
#endif
        {}

#ifdef RAWSTOR_TRACE_EVENTS
        ~EventReadV() {
            rawstor_trace_event_end(
                _trace_id, "EventReadV::~EventReadV()\n");
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(const std::string &message) {
            rawstor_trace_event_message(_trace_id, "%s\n", message.c_str());
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        inline void dispatch() {
            rawstor_trace_event_message(_trace_id, "dispatch()\n");
            try {
                Event::dispatch();
            } catch (std::exception &e) {
                rawstor_trace_event_message(
                    _trace_id, "dispatch(): error: %s\n", e.what());
            }
            rawstor_trace_event_message(
                _trace_id, "dispatch(): success\n");
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        inline virtual void set_error(int error) noexcept {
            Event::set_error(error);
            rawstor_trace_event_message(
                _trace_id, "error = %zd\n", _error);
        }
#endif
};


class EventPReadV: public EventP {
    private:
#ifdef RAWSTOR_TRACE_EVENTS
        void *_trace_id;
#endif

    public:
        EventPReadV(
            Queue &q, int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data):
            EventP(q, fd, buf, size, offset, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "pread(%d, %zu)\n", fd, size))
#endif
        {}

        EventPReadV(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data):
            EventP(q, fd, iov, niov, size, offset, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "preadv(%d, %zu)\n", fd, size))
#endif
        {}

#ifdef RAWSTOR_TRACE_EVENTS
        ~EventPReadV() {
            rawstor_trace_event_end(
                _trace_id, "EventPReadV::~EventPReadV()\n");
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(const std::string &message) {
            rawstor_trace_event_message(_trace_id, "%s\n", message.c_str());
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        inline void dispatch() {
            rawstor_trace_event_message(_trace_id, "dispatch()\n");
            try {
                Event::dispatch();
            } catch (std::exception &e) {
                rawstor_trace_event_message(
                    _trace_id, "dispatch(): error: %s\n", e.what());
            }
            rawstor_trace_event_message(
                _trace_id, "dispatch(): success\n");
        }
#endif
};


class EventWriteV: public Event {
    private:
#ifdef RAWSTOR_TRACE_EVENTS
        void *_trace_id;
#endif

    public:
        EventWriteV(
            Queue &q, int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data):
            Event(q, fd, buf, size, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "write(%d, %zu)\n", fd, size))
#endif
        {}

        EventWriteV(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data):
            Event(q, fd, iov, niov, size, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "writev(%d, %zu)\n", fd, size))
#endif
        {}

#ifdef RAWSTOR_TRACE_EVENTS
        ~EventWriteV() {
            rawstor_trace_event_end(
                _trace_id, "EventWriteV::~EventWriteV()\n");
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(const std::string &message) {
            rawstor_trace_event_message(_trace_id, "%s\n", message.c_str());
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        inline void dispatch() {
            rawstor_trace_event_message(_trace_id, "dispatch()\n");
            try {
                Event::dispatch();
            } catch (std::exception &e) {
                rawstor_trace_event_message(
                    _trace_id, "dispatch(): error: %s\n", e.what());
            }
            rawstor_trace_event_message(
                _trace_id, "dispatch(): success\n");
        }
#endif
};


class EventPWriteV: public EventP {
    private:
#ifdef RAWSTOR_TRACE_EVENTS
        void *_trace_id;
#endif

    public:
        EventPWriteV(
            Queue &q, int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data):
            EventP(q, fd, buf, size, offset, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "pwrite(%d, %zu)\n", fd, size))
#endif
        {}

        EventPWriteV(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data):
            EventP(q, fd, iov, niov, size, offset, cb, data)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "pwritev(%d, %zu)\n", fd, size))
#endif
        {}

#ifdef RAWSTOR_TRACE_EVENTS
        ~EventPWriteV() {
            rawstor_trace_event_end(
                _trace_id, "EventPWriteV::~EventPWriteV()\n");
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(const std::string &message) {
            rawstor_trace_event_message(_trace_id, "%s\n", message.c_str());
        }
#endif

#ifdef RAWSTOR_TRACE_EVENTS
        inline void dispatch() {
            rawstor_trace_event_message(_trace_id, "dispatch()\n");
            try {
                Event::dispatch();
            } catch (std::exception &e) {
                rawstor_trace_event_message(
                    _trace_id, "dispatch(): error: %s\n", e.what());
            }
            rawstor_trace_event_message(
                _trace_id, "dispatch(): success\n");
        }
#endif
};


}}} // rawstor::io


#endif // RAWSTORIO_POLL_EVENT_HPP
