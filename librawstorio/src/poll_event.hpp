#ifndef RAWSTORIO_POLL_EVENT_HPP
#define RAWSTORIO_POLL_EVENT_HPP

#include <rawstorio/task.hpp>

#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.hpp>
#include <rawstorstd/ringbuf.hpp>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

#include <list>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <cstddef>
#include <cstring>

namespace rawstor {
namespace io {
namespace poll {

class Queue;

class Event {
protected:
    Queue& _q;
    int _fd;
    std::unique_ptr<rawstor::io::Task> _t;
    ssize_t _result;
    int _error;

public:
    Event(Queue& q, int fd, std::unique_ptr<rawstor::io::Task> t) :
        _q(q),
        _fd(fd),
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
        if (error != 0) {
            std::ostringstream oss;
            oss << "error " << strerror(error);
            trace(__FILE__, __LINE__, __FUNCTION__, oss.str());
        }
#endif
        _error = error;
    }

    inline int error() const noexcept { return _error; }

    virtual void dispatch();

#ifdef RAWSTOR_TRACE_EVENTS
    void trace(
        const char* file, int line, const char* function,
        const std::string& message
    ) {
        _t->trace_event.message(file, line, function, message);
    }
#endif
    virtual bool is_completed() const noexcept = 0;
    virtual bool is_multiplex() const noexcept = 0;
    virtual bool is_multishot() const noexcept { return false; }
    virtual bool is_poll() const noexcept = 0;
    virtual bool is_read() const noexcept = 0;
    virtual bool is_write() const noexcept = 0;

    virtual ssize_t process() noexcept = 0;

    int fd() const noexcept { return _fd; }
};

class EventSimplex : public Event {
public:
    EventSimplex(Queue& q, int fd, std::unique_ptr<rawstor::io::Task> t) :
        Event(q, fd, std::move(t)) {}

    virtual ~EventSimplex() override = default;

    bool is_multiplex() const noexcept override final { return false; }
};

class EventMultiplex : public Event {
public:
    EventMultiplex(Queue& q, int fd, std::unique_ptr<rawstor::io::Task> t) :
        Event(q, fd, std::move(t)) {}

    virtual ~EventMultiplex() override = default;

    bool is_multiplex() const noexcept override final { return true; }

    virtual unsigned int niov() const noexcept = 0;

    virtual size_t shift(size_t shift) noexcept = 0;

    virtual void add_to_batch(std::vector<iovec>& iov) = 0;
};

class EventMultiplexScalar : public EventMultiplex {
protected:
    const void* _buf_at;
    size_t _size_at;

public:
    EventMultiplexScalar(
        Queue& q, int fd, const void* buf, size_t size,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventMultiplex(q, fd, std::move(t)),
        _buf_at(buf),
        _size_at(size) {}

    virtual ~EventMultiplexScalar() override = default;

    unsigned int niov() const noexcept override final { return 1; }

    bool is_completed() const noexcept override final { return _size_at == 0; }

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
    EventMultiplexVector(
        Queue& q, int fd, const iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventMultiplex(q, fd, std::move(t)),
        _niov_at(niov),
        _size_at(rawstor_iovec_size(iov, niov)) {
        _iov.reserve(_niov_at);
        for (unsigned int i = 0; i < _niov_at; ++i) {
            _iov.push_back(iov[i]);
        }
        _iov_at = _iov.data();
    }

    virtual ~EventMultiplexVector() override = default;

    unsigned int niov() const noexcept override final { return _niov_at; }

    bool is_completed() const noexcept override final { return _niov_at == 0; }

    size_t shift(size_t shift) noexcept override final;

    void add_to_batch(std::vector<iovec>& iov) override final;
};

class EventSimplexPoll : public EventSimplex {
private:
    unsigned int _mask;

public:
    EventSimplexPoll(
        Queue& q, int fd, unsigned int mask,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _mask(mask) {}

    virtual ~EventSimplexPoll() override = default;

    inline unsigned int mask() const noexcept { return _mask; }

    inline void set_result(ssize_t result) noexcept { _result = result; }

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return true; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexPollOneshot final : public EventSimplexPoll {
public:
    EventSimplexPollOneshot(
        Queue& q, int fd, unsigned int mask,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplexPoll(q, fd, mask, std::move(t)) {}
};

class EventSimplexPollMultishot final : public EventSimplexPoll {
public:
    EventSimplexPollMultishot(
        Queue& q, int fd, unsigned int mask,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplexPoll(q, fd, mask, std::move(t)) {}

    bool is_multishot() const noexcept override final { return true; }

    void dispatch() override;
};

class EventSimplexScalarRead final : public EventSimplex {
private:
    void* _buf;
    size_t _size;

public:
    EventSimplexScalarRead(
        Queue& q, int fd, void* buf, size_t size,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _buf(buf),
        _size(size) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexVectorRead final : public EventSimplex {
private:
    iovec* _iov;
    unsigned int _niov;

public:
    EventSimplexVectorRead(
        Queue& q, int fd, iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _iov(iov),
        _niov(niov) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexScalarPositionalRead final : public EventSimplex {
private:
    void* _buf;
    size_t _size;
    off_t _offset;

public:
    EventSimplexScalarPositionalRead(
        Queue& q, int fd, void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _buf(buf),
        _size(size),
        _offset(offset) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexVectorPositionalRead final : public EventSimplex {
private:
    iovec* _iov;
    unsigned int _niov;
    off_t _offset;

public:
    EventSimplexVectorPositionalRead(
        Queue& q, int fd, iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _iov(iov),
        _niov(niov),
        _offset(offset) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexScalarRecv final : public EventSimplex {
private:
    void* _buf;
    size_t _size;
    unsigned int _flags;

public:
    EventSimplexScalarRecv(
        Queue& q, int fd, void* buf, size_t size, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _buf(buf),
        _size(size),
        _flags(flags) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexVectorRecvMultishotEntry final {
private:
    std::vector<char> _data;
    size_t _result;

public:
    EventSimplexVectorRecvMultishotEntry(size_t size) :
        _data(size),
        _result(0) {}

    EventSimplexVectorRecvMultishotEntry(
        const EventSimplexVectorRecvMultishotEntry&
    ) = delete;

    EventSimplexVectorRecvMultishotEntry(
        EventSimplexVectorRecvMultishotEntry&& other
    ) noexcept :
        _data(std::move(other._data)),
        _result(std::exchange(other._result, 0)) {}

    EventSimplexVectorRecvMultishotEntry&
    operator=(const EventSimplexVectorRecvMultishotEntry&) = delete;

    EventSimplexVectorRecvMultishotEntry&
    operator=(EventSimplexVectorRecvMultishotEntry&& other) noexcept {
        EventSimplexVectorRecvMultishotEntry temp(std::move(other));
        swap(temp);
        return *this;
    }

    inline void* data() noexcept { return _data.data(); }
    inline size_t size() const noexcept { return _data.size(); }
    inline size_t result() const noexcept { return _result; }
    inline void set_result(size_t result) noexcept { _result = result; };

    void swap(EventSimplexVectorRecvMultishotEntry& other) noexcept {
        std::swap(_data, other._data);
        std::swap(_result, other._result);
    }
};

class EventSimplexVectorRecvMultishot final : public EventSimplex {
private:
    size_t _entry_size;
    size_t _pending_offset;
    size_t _pending_size;
    rawstor::RingBuf<EventSimplexVectorRecvMultishotEntry> _pending_entries;
    unsigned int _flags;

public:
    EventSimplexVectorRecvMultishot(
        Queue& q, int fd, size_t entry_size, unsigned int entries,
        unsigned int flags, std::unique_ptr<rawstor::io::TaskVectorExternal> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _entry_size(entry_size),
        _pending_offset(0),
        _pending_size(0),
        _pending_entries(entries),
        _flags(flags) {}

    ssize_t process() noexcept override final;
    void dispatch() override;

    bool is_completed() const noexcept override final;
    bool is_multishot() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexMessageRead final : public EventSimplex {
private:
    msghdr* _msg;
    unsigned int _flags;

public:
    EventSimplexMessageRead(
        Queue& q, int fd, msghdr* msg, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _msg(msg),
        _flags(flags) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }
};

class EventMultiplexScalarWrite final : public EventMultiplexScalar {
public:
    EventMultiplexScalarWrite(
        Queue& q, int fd, const void* buf, size_t size,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventMultiplexScalar(q, fd, buf, size, std::move(t)) {}

    ssize_t process() noexcept override final;

    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }
};

class EventMultiplexVectorWrite final : public EventMultiplexVector {
public:
    EventMultiplexVectorWrite(
        Queue& q, int fd, const iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventMultiplexVector(q, fd, iov, niov, std::move(t)) {}

    ssize_t process() noexcept override final;

    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }
};

class EventSimplexScalarPositionalWrite final : public EventSimplex {
private:
    const void* _buf;
    size_t _size;
    off_t _offset;

public:
    EventSimplexScalarPositionalWrite(
        Queue& q, int fd, const void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _buf(buf),
        _size(size),
        _offset(offset) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }
};

class EventSimplexVectorPositionalWrite final : public EventSimplex {
private:
    const iovec* _iov;
    unsigned int _niov;
    off_t _offset;

public:
    EventSimplexVectorPositionalWrite(
        Queue& q, int fd, const iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _iov(iov),
        _niov(niov),
        _offset(offset) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }
};

class EventSimplexScalarSend final : public EventSimplex {
private:
    const void* _buf;
    size_t _size;
    unsigned int _flags;

public:
    EventSimplexScalarSend(
        Queue& q, int fd, const void* buf, size_t size, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _buf(buf),
        _size(size),
        _flags(flags) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }
};

class EventSimplexMessageWrite final : public EventSimplex {
private:
    const msghdr* _msg;
    unsigned int _flags;

public:
    EventSimplexMessageWrite(
        Queue& q, int fd, const msghdr* msg, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) :
        EventSimplex(q, fd, std::move(t)),
        _msg(msg),
        _flags(flags) {}

    ssize_t process() noexcept override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_POLL_EVENT_HPP
