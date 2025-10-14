#ifndef RAWSTORIO_POLL_EVENT_HPP
#define RAWSTORIO_POLL_EVENT_HPP

#include <rawstorio/task.hpp>
#include <rawstorio/event.hpp>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

#include <vector>

#include <cstddef>
#include <cstdio>

namespace rawstor {
namespace io {
namespace poll {


class Event: public RawstorIOEvent {
    private:
        std::vector<iovec> _iov;
        iovec *_iov_at;
        unsigned int _niov_at;
        ssize_t _result;
        int _error;

    public:
        Event(
            Queue &q, int fd,
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Task> t):
            RawstorIOEvent(q, fd, size, std::move(t)),
            _iov(1, (iovec){.iov_base = buf, .iov_len = size}),
            _iov_at(_iov.data()),
            _niov_at(1),
            _result(0),
            _error(0)
        {}

        Event(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Task> t):
            RawstorIOEvent(q, fd, size, std::move(t)),
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
    private:
        off_t _offset;

    public:
        EventP(
            Queue &q, int fd,
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Task> t):
            Event(q, fd, buf, size, std::move(t)),
            _offset(offset)
        {}

        EventP(
            Queue &q, int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Task> t):
            Event(q, fd, iov, niov, size, std::move(t)),
            _offset(offset)
        {}

        inline off_t offset() const noexcept {
            return _offset;
        }

        size_t shift(size_t shift);
};


}}} // rawstor::io


#endif // RAWSTORIO_POLL_EVENT_HPP
