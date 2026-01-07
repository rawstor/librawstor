#ifndef RAWSTORIO_URING_EVENT_HPP
#define RAWSTORIO_URING_EVENT_HPP

#include <rawstorstd/logging.h>

#include <rawstorio/task.hpp>

#include <memory>
#include <vector>

namespace rawstor {
namespace io {
namespace uring {

class Queue;

class Event {
protected:
    Queue& _q;
    std::unique_ptr<rawstor::io::Task> _t;
    size_t _result;
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

    virtual void prep() = 0;

    void dispatch();

    virtual void set_result(ssize_t res) noexcept = 0;

    inline int error() const noexcept { return _error; }

    virtual bool completed() const noexcept = 0;

#ifdef RAWSTOR_TRACE_EVENTS
    void trace(
        const char* file, int line, const char* function,
        const std::string& message
    ) {
        _t->trace(file, line, function, message);
    }
#endif
};

class EventPoll final : public Event {
public:
    EventPoll(Queue& q, std::unique_ptr<rawstor::io::TaskPoll> t) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept override;

    bool completed() const noexcept override { return true; }
};

class EventScalar : public Event {
protected:
    void* _buf_at;
    size_t _size_at;

public:
    EventScalar(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        Event(q, std::move(t)),
        _buf_at(static_cast<rawstor::io::TaskScalar*>(_t.get())->buf()),
        _size_at(static_cast<rawstor::io::TaskScalar*>(_t.get())->size()) {}

    void set_result(ssize_t res) noexcept override;

    bool completed() const noexcept override { return _size_at == 0; }
};

class EventVector : public Event {
protected:
    std::vector<iovec> _iov;
    iovec* _iov_at;
    unsigned int _niov_at;
    size_t _size_at;

public:
    EventVector(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        Event(q, std::move(t)),
        _niov_at(static_cast<rawstor::io::TaskVector*>(_t.get())->niov()),
        _size_at(static_cast<rawstor::io::TaskVector*>(_t.get())->size()) {
        iovec* iov = static_cast<rawstor::io::TaskVector*>(_t.get())->iov();
        _iov.reserve(_niov_at);
        for (unsigned int i = 0; i < _niov_at; ++i) {
            _iov.push_back(iov[i]);
        }
        _iov_at = _iov.data();
    }

    void set_result(ssize_t res) noexcept override;

    bool completed() const noexcept override { return _size_at == 0; }
};

class EventScalarRead final : public EventScalar {
public:
    EventScalarRead(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        EventScalar(q, std::move(t)) {}

    void prep() override;
};

class EventVectorRead final : public EventVector {
public:
    EventVectorRead(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        EventVector(q, std::move(t)) {}

    void prep() override;
};

class EventScalarPositionalRead final : public Event {
public:
    EventScalarPositionalRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept { _result = res; }

    bool completed() const noexcept override { return true; }
};

class EventVectorPositionalRead final : public Event {
public:
    EventVectorPositionalRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept { _result = res; }

    bool completed() const noexcept override { return true; }
};

class EventMessageRead final : public Event {
public:
    EventMessageRead(Queue& q, std::unique_ptr<rawstor::io::TaskMessage> t) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept { _result = res; }

    bool completed() const noexcept override { return true; }
};

class EventScalarWrite final : public EventScalar {
public:
    EventScalarWrite(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        EventScalar(q, std::move(t)) {}

    void prep() override;
};

class EventVectorWrite final : public EventVector {
public:
    EventVectorWrite(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        EventVector(q, std::move(t)) {}

    void prep() override;
};

class EventScalarPositionalWrite final : public Event {
public:
    EventScalarPositionalWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept { _result = res; }

    bool completed() const noexcept override { return true; }
};

class EventVectorPositionalWrite final : public Event {
public:
    EventVectorPositionalWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept { _result = res; }

    bool completed() const noexcept override { return true; }
};

class EventMessageWrite final : public Event {
public:
    EventMessageWrite(Queue& q, std::unique_ptr<rawstor::io::TaskMessage> t) :
        Event(q, std::move(t)) {}

    void prep() override;

    void set_result(ssize_t res) noexcept { _result = res; }

    bool completed() const noexcept override { return true; }
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_EVENT_HPP
