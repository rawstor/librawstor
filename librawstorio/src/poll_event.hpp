#ifndef RAWSTORIO_POLL_EVENT_HPP
#define RAWSTORIO_POLL_EVENT_HPP

#include <rawstorio/task.hpp>

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
    Queue& _q;
    std::unique_ptr<rawstor::io::Task> _t;
    ssize_t _result;
    int _error;

public:
    Event(Queue& q, std::unique_ptr<rawstor::io::Task> t) :
        _q(q),
        _t(std::move(t)),
        _result(0),
        _error(0) {}
    Event(const Event&) = delete;
    Event(Event&&) = delete;
    virtual ~Event() = default;

    Event& operator=(const Event&) = delete;
    Event& operator=(Event&&) = delete;

    inline void set_error(int error) noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
        std::ostringstream oss;
        oss << "error " << error;
        trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
        _error = error;
    }

    inline int error() const noexcept { return _error; }

    void dispatch();

#ifdef RAWSTOR_TRACE_EVENTS
    void trace(
        const char* file, int line, const char* function,
        const std::string& message
    ) {
        _t->trace(file, line, function, message);
    }
#endif
    virtual bool multiplex() const noexcept = 0;

    virtual ssize_t process() noexcept = 0;
};

class EventSimplex : public Event {
public:
    EventSimplex(Queue& q, std::unique_ptr<rawstor::io::Task> t) :
        Event(q, std::move(t)) {}

    virtual ~EventSimplex() override = default;

    bool multiplex() const noexcept override final { return false; };
};

class EventMultiplex : public Event {
public:
    EventMultiplex(Queue& q, std::unique_ptr<rawstor::io::Task> t) :
        Event(q, std::move(t)) {}

    virtual ~EventMultiplex() override = default;

    bool multiplex() const noexcept override final { return true; };

    virtual unsigned int niov() const noexcept = 0;

    virtual bool completed() const noexcept = 0;

    virtual size_t shift(size_t shift) noexcept = 0;

    virtual void add_to_batch(std::vector<iovec>& iov) = 0;
};

class EventMultiplexScalar : public EventMultiplex {
protected:
    void* _buf_at;
    size_t _size_at;

public:
    EventMultiplexScalar(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        EventMultiplex(q, std::move(t)),
        _buf_at(static_cast<rawstor::io::TaskScalar*>(_t.get())->buf()),
        _size_at(static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {}

    virtual ~EventMultiplexScalar() override = default;

    unsigned int niov() const noexcept override final { return 1; }

    bool completed() const noexcept override final { return _size_at == 0; }

    size_t shift(size_t shift) noexcept override final;

    void add_to_batch(std::vector<iovec>& iov) override final;
};

class EventMultiplexVector : public EventMultiplex {
protected:
    std::vector<iovec> _iov;
    iovec* _iov_at;
    unsigned int _niov_at;
    size_t _size_at;

public:
    EventMultiplexVector(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        EventMultiplex(q, std::move(t)),
        _niov_at(static_cast<rawstor::io::TaskVector*>(_t.get())->niov()),
        _size_at(static_cast<rawstor::io::TaskVector*>(_t.get())->size()) {
        iovec* iov = static_cast<rawstor::io::TaskVector*>(_t.get())->iov();
        _iov.reserve(_niov_at);
        for (unsigned int i = 0; i < _niov_at; ++i) {
            _iov.push_back(iov[i]);
        }
        _iov_at = _iov.data();
    }

    virtual ~EventMultiplexVector() override = default;

    unsigned int niov() const noexcept override final { return _niov_at; }

    bool completed() const noexcept override final { return _niov_at == 0; }

    size_t shift(size_t shift) noexcept override final;

    void add_to_batch(std::vector<iovec>& iov) override final;
};

class EventSimplexPoll final : public EventSimplex {
public:
    EventSimplexPoll(Queue& q, std::unique_ptr<rawstor::io::TaskPoll> t) :
        EventSimplex(q, std::move(t)) {}

    inline unsigned int mask() const noexcept {
        return static_cast<rawstor::io::TaskPoll*>(_t.get())->mask();
    }

    ssize_t process() noexcept override final;

    void set_result(short revents) noexcept;
};

class EventSimplexScalarRead final : public EventSimplex {
public:
    EventSimplexScalarRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexVectorRead final : public EventSimplex {
public:
    EventSimplexVectorRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskVector> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexScalarPositionalRead final : public EventSimplex {
public:
    EventSimplexScalarPositionalRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexVectorPositionalRead final : public EventSimplex {
public:
    EventSimplexVectorPositionalRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexMessageRead final : public EventSimplex {
public:
    EventSimplexMessageRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskMessage> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventMultiplexScalarWrite final : public EventMultiplexScalar {
public:
    EventMultiplexScalarWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t
    ) :
        EventMultiplexScalar(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventMultiplexVectorWrite final : public EventMultiplexVector {
public:
    EventMultiplexVectorWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskVector> t
    ) :
        EventMultiplexVector(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexScalarPositionalWrite final : public EventSimplex {
public:
    EventSimplexScalarPositionalWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexVectorPositionalWrite final : public EventSimplex {
public:
    EventSimplexVectorPositionalWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

class EventSimplexMessageWrite final : public EventSimplex {
public:
    EventSimplexMessageWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskMessage> t
    ) :
        EventSimplex(q, std::move(t)) {}

    ssize_t process() noexcept override final;
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_POLL_EVENT_HPP
