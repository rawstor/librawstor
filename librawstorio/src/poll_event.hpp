#ifndef RAWSTORIO_POLL_EVENT_HPP
#define RAWSTORIO_POLL_EVENT_HPP

#include <rawstorio/task.hpp>

#include <rawstorstd/logging.hpp>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

#include <memory>
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
    Queue& _q;
    std::unique_ptr<rawstor::io::Task> _t;
    std::vector<iovec> _iov;
    iovec* _iov_at;
    unsigned int _niov_at;
    size_t _size;
    ssize_t _result;
    int _error;

public:
    Event(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        _q(q),
        _t(std::move(t)),
        _iov(
            1,
            (iovec){
                .iov_base =
                    static_cast<rawstor::io::TaskScalar*>(_t.get())->buf(),
                .iov_len =
                    static_cast<rawstor::io::TaskScalar*>(_t.get())->size(),
            }
        ),
        _iov_at(_iov.data()),
        _niov_at(1),
        _size(static_cast<rawstor::io::TaskScalar*>(_t.get())->size()),
        _result(0),
        _error(0) {}

    Event(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        _q(q),
        _t(std::move(t)),
        _niov_at(static_cast<rawstor::io::TaskVector*>(_t.get())->niov()),
        _size(static_cast<rawstor::io::TaskVector*>(_t.get())->size()),
        _result(0),
        _error(0) {
        iovec* iov = static_cast<rawstor::io::TaskVector*>(_t.get())->iov();
        _iov.reserve(_niov_at);
        for (unsigned int i = 0; i < _niov_at; ++i) {
            _iov.push_back(iov[i]);
        }
        _iov_at = _iov.data();
    }

    Event(const Event&) = delete;
    Event(Event&&) = delete;

    virtual ~Event() = default;

    Event& operator=(const Event&) = delete;
    Event& operator=(Event&&) = delete;

    inline void set_error(int error) noexcept { _error = error; }

    inline iovec* iov() const noexcept { return _iov_at; }

    inline unsigned int niov() const noexcept { return _niov_at; }

    inline bool completed() const noexcept { return _niov_at == 0; }

    void dispatch();

    void add_iov(std::vector<iovec>& iov);

    virtual size_t shift(size_t shift);

#ifdef RAWSTOR_TRACE_EVENTS
    void trace(
        const char* file, int line, const char* function,
        const std::string& message
    ) {
        _t->trace_event.message(file, line, function, message);
    }
#endif
};

class EventP : public Event {
private:
    off_t _offset_at;

public:
    EventP(Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t) :
        Event(q, std::move(t)),
        _offset_at(
            static_cast<rawstor::io::TaskScalarPositional*>(_t.get())->offset()
        ) {}

    EventP(Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t) :
        Event(q, std::move(t)),
        _offset_at(
            static_cast<rawstor::io::TaskVectorPositional*>(_t.get())->offset()
        ) {}

    inline off_t offset() const noexcept { return _offset_at; }

    size_t shift(size_t shift) override;
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_POLL_EVENT_HPP
