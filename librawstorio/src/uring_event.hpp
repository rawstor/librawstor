#ifndef RAWSTORIO_URING_EVENT_HPP
#define RAWSTORIO_URING_EVENT_HPP

#include <rawstorstd/logging.h>

#include <rawstorio/task.hpp>

#include <memory>
#include <sstream>

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

    inline void set_result(ssize_t res) noexcept {
        if (res >= 0) {
            _result += res;
        } else {
            _error = -res;
#ifdef RAWSTOR_TRACE_EVENTS
            std::ostringstream oss;
            oss << "error " << _error;
            trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
#endif
        }
    }

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
};

class EventScalarRead final : public Event {
public:
    EventScalarRead(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventVectorRead final : public Event {
public:
    EventVectorRead(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventScalarPositionalRead final : public Event {
public:
    EventScalarPositionalRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventVectorPositionalRead final : public Event {
public:
    EventVectorPositionalRead(
        Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventMessageRead final : public Event {
public:
    EventMessageRead(Queue& q, std::unique_ptr<rawstor::io::TaskMessage> t) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventScalarWrite final : public Event {
public:
    EventScalarWrite(Queue& q, std::unique_ptr<rawstor::io::TaskScalar> t) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventVectorWrite final : public Event {
public:
    EventVectorWrite(Queue& q, std::unique_ptr<rawstor::io::TaskVector> t) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventScalarPositionalWrite final : public Event {
public:
    EventScalarPositionalWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskScalarPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventVectorPositionalWrite final : public Event {
public:
    EventVectorPositionalWrite(
        Queue& q, std::unique_ptr<rawstor::io::TaskVectorPositional> t
    ) :
        Event(q, std::move(t)) {}

    void prep() override;
};

class EventMessageWrite final : public Event {
public:
    EventMessageWrite(Queue& q, std::unique_ptr<rawstor::io::TaskMessage> t) :
        Event(q, std::move(t)) {}

    void prep() override;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_EVENT_HPP
