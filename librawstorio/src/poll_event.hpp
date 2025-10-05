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
#ifdef RAWSTOR_TRACE_EVENTS
        void *_trace_id;
#endif

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
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "Event(%d, %zu)\n", fd, size))
#endif
        {}

        Event(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data):
            rawstor::io::Event(q, fd, size, cb, data),
            _niov_at(niov),
            _result(0),
            _error(0)
#ifdef RAWSTOR_TRACE_EVENTS
            , _trace_id(rawstor_trace_event_begin(
                "Event(%d, %zu)\n", fd, size))
#endif
        {
            _iov.reserve(niov);
            for (unsigned int i = 0; i < niov; ++i) {
                _iov.push_back(iov[i]);
            }
            _iov_at = _iov.data();
        }

        virtual ~Event() {
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_end(
                _trace_id, "Event::~Event()\n");
#endif
        }

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(const std::string &message) {
            rawstor_trace_event_message(_trace_id, "%s\n", message.c_str());
        }
#endif

        inline size_t result() const noexcept {
            return _result;
        }

        inline int error() const noexcept {
            return _error;
        }

        inline virtual void set_error(int error) noexcept {
            _error = error;
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_message(
                _trace_id, "error = %zd\n", _error);
#endif
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

#ifdef RAWSTOR_TRACE_EVENTS
        inline void dispatch() {
            rawstor_trace_event_message(_trace_id, "dispatch()\n");
            try {
                rawstor::io::Event::dispatch();
            } catch (std::exception &e) {
                rawstor_trace_event_message(
                    _trace_id, "dispatch(): error: %s\n", e.what());
            }
            rawstor_trace_event_message(
                _trace_id, "dispatch(): success\n");
        }
#endif

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


}}} // rawstor::io


#endif // RAWSTORIO_POLL_EVENT_HPP
