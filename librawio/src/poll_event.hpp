#ifndef RAWIO_POLL_EVENT_HPP
#define RAWIO_POLL_EVENT_HPP

#include <rawio/stream.hpp>

#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/ringbuf.hpp>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

#include <coroutine>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include <cstddef>
#include <cstring>

namespace rawio {
namespace poll {

class Queue;

class Event {
protected:
    Queue& _q;
    int _fd;
    ssize_t _result;
    int _error;

    // Set via attach() (called from Queue::_attach(), i.e. from some
    // Awaitable<T>::await_suspend()) once whoever co_await-ed this
    // operation is known. resolve_one_shot()/resolve_one_shot_raw() write
    // the outcome into _value_ptr/_error_ptr and resume _handle -- see
    // rawio::Awaitable<T> in <rawio/awaitable.hpp> for the other end of
    // this contract.
    std::coroutine_handle<> _handle;
    size_t* _value_ptr;
    int* _error_ptr;

    // Optional override of the default "resolve and resume" dispatch
    // behavior. Empty for almost every event; connect()'s
    // EINPROGRESS-then-poll(POLLOUT)-then-getsockopt retry chain is the
    // one case that needs to inspect an intermediate result and decide
    // whether to resolve now or hand the attachment off to a follow-up
    // event (see adopt_attachment()).
    std::function<void(Event&)> _on_dispatch;

public:
    rawstd::TraceEvent trace_event;

    Event(Queue& q, int fd, const rawstd::TraceEvent& trace_event) :
        _q(q),
        _fd(fd),
        _result(0),
        _error(0),
        _handle(),
        _value_ptr(nullptr),
        _error_ptr(nullptr),
        trace_event(trace_event) {}
    Event(const Event&) = delete;
    Event(Event&&) = delete;
    virtual ~Event() = default;

    Event& operator=(const Event&) = delete;
    Event& operator=(Event&&) = delete;

    inline void set_error(int error) noexcept {
#ifdef RAWSTD_TRACE_EVENTS
        if (error != 0) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "error %s\n", strerror(error)
            );
        }
#endif
        _error = error;
    }

    inline int error() const noexcept { return _error; }
    inline ssize_t result() const noexcept { return _result; }

    inline void attach(
        std::coroutine_handle<> h, size_t* value_ptr, int* error_ptr
    ) noexcept {
        _handle = h;
        _value_ptr = value_ptr;
        _error_ptr = error_ptr;
    }

    // Transfers a pending attach()-ment from `other` to *this, clearing
    // it on `other` -- used when one syscall-driven Event's completion
    // determines that a *different* Event will actually deliver the
    // eventual result (connect()'s retry chain).
    inline void adopt_attachment(Event& other) noexcept {
        _handle = other._handle;
        _value_ptr = other._value_ptr;
        _error_ptr = other._error_ptr;
        other._handle = nullptr;
        other._value_ptr = nullptr;
        other._error_ptr = nullptr;
    }

    inline void
    set_on_dispatch(std::function<void(Event&)>&& on_dispatch) noexcept {
        _on_dispatch = std::move(on_dispatch);
    }

    // Resolves the attached co_await (if any) from the current
    // _result(non-negative on success)/_error(errno on failure) split
    // fields, and resumes it. Deliberately NOT noexcept: resuming a
    // rawstd::DetachedTask (the rawio.cpp C shim's adapters are the only
    // thing that ever attaches one here) can legitimately throw --
    // DetachedTask::promise_type::unhandled_exception() rethrows by
    // design, see its doc comment -- and that exception must propagate
    // all the way out to _wait_timeout()'s own try/catch, not be turned
    // into a std::terminate() by a noexcept boundary partway there.
    inline void resolve_one_shot() {
        if (_error) {
            if (_value_ptr) {
                *_value_ptr = 0;
            }
            if (_error_ptr) {
                *_error_ptr = _error;
            }
        } else {
            if (_value_ptr) {
                *_value_ptr = static_cast<size_t>(_result);
            }
            if (_error_ptr) {
                *_error_ptr = 0;
            }
        }
        if (_handle) {
            _handle.resume();
        }
    }

    // Same, but for EventEval's single-combined-field convention
    // (negative = -errno, non-negative = success value). See
    // resolve_one_shot()'s comment for why this isn't noexcept either.
    inline void resolve_one_shot_raw(ssize_t raw_result) {
        if (raw_result < 0) {
            set_error(static_cast<int>(-raw_result));
            _result = 0;
        } else {
            _result = raw_result;
        }
        resolve_one_shot();
    }

    virtual void dispatch() = 0;

    virtual bool is_completed() const noexcept = 0;
    virtual bool is_multiplex() const noexcept = 0;
    virtual bool is_multishot() const noexcept { return false; }
    virtual bool is_poll() const noexcept = 0;
    virtual bool is_accept() const noexcept = 0;
    virtual bool is_read() const noexcept = 0;
    virtual bool is_write() const noexcept = 0;

    virtual ssize_t process() noexcept = 0;

    int fd() const noexcept { return _fd; }
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

/**
 * Shared single-slot "pull" backend for poll_multishot()/
 * accept_multishot() -- the poll-backend counterpart of uring::
 * SingleSlotStreamBackend (see uring_queue.cpp's doc comment for the
 * design and the same-batch-dedup/overflow rules; identical here except
 * `_q`/`cancel()`/`dispatch_generation()` go through rawio::poll::Queue
 * instead of rawio::uring::Queue). `EventSimplexPollMultishot`/
 * `EventSimplexAcceptMultishot` each own one of these via a shared_ptr
 * (not by inheriting it directly: the Event itself is unique_ptr-owned by
 * Session/`_cqes`, while the stream wrapper handed back to the caller
 * needs shared, independent ownership of the backend).
 */
template <typename BackendBase, bool dedup>
class SingleSlotStreamBackend final : public BackendBase {
private:
    Queue& _q;
    unsigned int _last_generation;

    std::coroutine_handle<> _waiter;
    int* _waiter_out;
    int* _waiter_error;

    bool _has_pending;
    int _pending_value;
    int _pending_error;
    bool _pending_overflow;

    bool _closed;
    bool _terminated;
    int _terminal_error;

    Event* _event;

public:
    SingleSlotStreamBackend(Queue& q, unsigned int last_generation);

    inline void set_event(Event* event) noexcept { _event = event; }

    bool try_produce(int& out, int& error) noexcept override;
    void set_waiter(
        std::coroutine_handle<> h, int* out, int* error
    ) noexcept override;
    void close() noexcept override;
    rawio::Event* event() const noexcept override { return _event; }

    // Called from EventSimplexPollMultishot::dispatch()/
    // EventSimplexAcceptMultishot::dispatch() with the already-resolved
    // (setup_fd()-applied, for accept) negative-errno-or-non-negative-value
    // convention. Deliberately NOT noexcept -- see
    // Event::resolve_one_shot()'s comment.
    void on_completion(int value, int error);
};

using PollMultishotBackend =
    SingleSlotStreamBackend<rawio::PollStream::Backend, /*dedup=*/true>;
using AcceptMultishotBackend =
    SingleSlotStreamBackend<rawio::AcceptStream::Backend, /*dedup=*/false>;

/**
 * RecvStream::Backend for the poll backend's recv_multishot(): owns the
 * same "keep receiving into local buffers until EAGAIN or full"
 * accounting `EventSimplexVectorRecvMultishot::process()` always had
 * (`_pending_entries`/`_pending_offset`/`_pending_size`, now living here
 * instead of on the Event itself, for the same shared-ownership reason as
 * SingleSlotStreamBackend above), plus the produce-or-park logic shared
 * with uring::BufferRing (see its doc comment for the exact
 * want/terminal-error precedence rules, identical here).
 */
class RecvMultishotBackend final : public rawio::RecvStream::Backend {
private:
    void _extract(size_t want, rawio::RecvStream::Item& out);

    Queue& _q;
    size_t _pending_offset;
    size_t _pending_size;
    rawstd::RingBuf<EventSimplexVectorRecvMultishotEntry> _pending_entries;

    std::coroutine_handle<> _waiter;
    size_t _waiter_want;
    rawio::RecvStream::Item* _waiter_item;
    int* _waiter_error;

    bool _has_terminal;
    int _terminal_error;
    bool _closed;

    Event* _event;

public:
    RecvMultishotBackend(Queue& q, unsigned int entries);

    inline bool full() const noexcept { return _pending_entries.full(); }

    inline void
    add_entry(std::unique_ptr<EventSimplexVectorRecvMultishotEntry> entry) {
        _pending_size += entry->result();
        _pending_entries.push(std::move(entry));
    }

    inline void set_event(Event* event) noexcept { _event = event; }

    // Called from EventSimplexVectorRecvMultishot::dispatch() once per
    // readiness round, after process() has already drained whatever it
    // could into add_entry() above; `error` is the Event's own _error
    // (0 if nothing went wrong this round). Returns true once this
    // backend has reached a terminal condition (which can happen here
    // even if `error` was 0: the provided-buffer pool running dry is
    // detected independently, inside this call) -- the caller must then
    // make sure its own Event::_error reflects that too, so the outer
    // dispatch loop's "stop re-arming a multishot event once it has
    // errored" check actually stops re-arming this one.
    // Deliberately NOT noexcept -- see Event::resolve_one_shot()'s
    // comment.
    bool on_arrival(int error);

    bool try_produce(
        size_t want, rawio::RecvStream::Item& out, int& error
    ) noexcept override;
    void set_waiter(
        std::coroutine_handle<> h, size_t want, rawio::RecvStream::Item* out,
        int* error
    ) noexcept override;
    void close() noexcept override;
    rawio::Event* event() const noexcept override { return _event; }
};

class EventEval final : public Event {
private:
    std::function<int()> _eval;

public:
    EventEval(
        Queue& q, const rawstd::TraceEvent& trace_event,
        std::function<int()>&& eval
    ) :
        Event(q, -1, trace_event),
        _eval(std::move(eval)) {}

    void dispatch() override;

    bool is_completed() const noexcept override { return true; }
    bool is_multiplex() const noexcept override { return false; }
    bool is_multishot() const noexcept override { return false; }
    bool is_poll() const noexcept override { return false; }
    bool is_accept() const noexcept override { return false; }
    bool is_read() const noexcept override { return false; }
    bool is_write() const noexcept override { return false; }

    ssize_t process() noexcept override;
};

class EventSimplex : public Event {
public:
    EventSimplex(Queue& q, int fd, const rawstd::TraceEvent& trace_event) :
        Event(q, fd, trace_event) {}

    virtual ~EventSimplex() override = default;

    bool is_multiplex() const noexcept override final { return false; }

    // Default one-shot behavior shared by every EventSimplex-derived
    // class that doesn't need anything fancier: resolve_one_shot(), or
    // _on_dispatch(*this) if set. Not `final` -- the multishot siblings
    // (EventSimplexPollMultishot/EventSimplexAcceptMultishot/
    // EventSimplexVectorRecvMultishot) still override this with their
    // own multishot-specific dispatch.
    void dispatch() override;
};

class EventMultiplex : public Event {
public:
    EventMultiplex(Queue& q, int fd, const rawstd::TraceEvent& trace_event) :
        Event(q, fd, trace_event) {}

    virtual ~EventMultiplex() override = default;

    void dispatch() override final;

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
        const rawstd::TraceEvent& trace_event
    ) :
        EventMultiplex(q, fd, trace_event),
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
        const rawstd::TraceEvent& trace_event
    ) :
        EventMultiplex(q, fd, trace_event),
        _niov_at(niov),
        _size_at(rawstd_iovec_size(iov, niov)) {
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
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _mask(mask) {}

    virtual ~EventSimplexPoll() override = default;

    inline unsigned int mask() const noexcept { return _mask; }

    inline void set_result(ssize_t result) noexcept { _result = result; }

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return true; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexPollOneshot final : public EventSimplexPoll {
public:
    EventSimplexPollOneshot(
        Queue& q, int fd, unsigned int mask,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplexPoll(q, fd, mask, trace_event) {}
};

class EventSimplexPollMultishot final : public EventSimplexPoll {
private:
    std::shared_ptr<PollMultishotBackend> _backend;

public:
    EventSimplexPollMultishot(
        Queue& q, int fd, unsigned int mask,
        const rawstd::TraceEvent& trace_event,
        std::shared_ptr<PollMultishotBackend> backend
    ) :
        EventSimplexPoll(q, fd, mask, trace_event),
        _backend(std::move(backend)) {}

    void dispatch() override final;

    bool is_multishot() const noexcept override final { return true; }
};

class EventSimplexAccept : public EventSimplex {
public:
    EventSimplexAccept(
        Queue& q, int fd, const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event) {}

    virtual ~EventSimplexAccept() override = default;

    inline void set_result(ssize_t result) noexcept { _result = result; }

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return true; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return false; }
};

class EventSimplexAcceptOneshot final : public EventSimplexAccept {
private:
    sockaddr* _addr;
    socklen_t* _addrlen;

public:
    EventSimplexAcceptOneshot(
        Queue& q, int fd, sockaddr* addr, socklen_t* addrlen,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplexAccept(q, fd, trace_event),
        _addr(addr),
        _addrlen(addrlen) {}

    inline sockaddr* addr() const noexcept { return _addr; }
    inline socklen_t* addrlen() const noexcept { return _addrlen; }

    ssize_t process() noexcept override final;
};

class EventSimplexAcceptMultishot final : public EventSimplexAccept {
private:
    std::shared_ptr<AcceptMultishotBackend> _backend;

public:
    EventSimplexAcceptMultishot(
        Queue& q, int fd, const rawstd::TraceEvent& trace_event,
        std::shared_ptr<AcceptMultishotBackend> backend
    ) :
        EventSimplexAccept(q, fd, trace_event),
        _backend(std::move(backend)) {}

    void dispatch() override final;

    bool is_multishot() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

class EventSimplexScalarRead final : public EventSimplex {
private:
    void* _buf;
    size_t _size;

public:
    EventSimplexScalarRead(
        Queue& q, int fd, void* buf, size_t size,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _buf(buf),
        _size(size) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexVectorRead final : public EventSimplex {
private:
    iovec* _iov;
    unsigned int _niov;

public:
    EventSimplexVectorRead(
        Queue& q, int fd, iovec* iov, unsigned int niov,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _iov(iov),
        _niov(niov) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexScalarPositionalRead final : public EventSimplex {
private:
    void* _buf;
    size_t _size;
    off_t _offset;

public:
    EventSimplexScalarPositionalRead(
        Queue& q, int fd, void* buf, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _buf(buf),
        _size(size),
        _offset(offset) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexVectorPositionalRead final : public EventSimplex {
private:
    iovec* _iov;
    unsigned int _niov;
    off_t _offset;

public:
    EventSimplexVectorPositionalRead(
        Queue& q, int fd, iovec* iov, unsigned int niov, off_t offset,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _iov(iov),
        _niov(niov),
        _offset(offset) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexScalarRecv final : public EventSimplex {
private:
    void* _buf;
    size_t _size;
    unsigned int _flags;

public:
    EventSimplexScalarRecv(
        Queue& q, int fd, void* buf, size_t size, unsigned int flags,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _buf(buf),
        _size(size),
        _flags(flags) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexVectorRecvMultishot final : public EventSimplex {
private:
    size_t _entry_size;
    unsigned int _flags;
    std::shared_ptr<RecvMultishotBackend> _backend;

public:
    EventSimplexVectorRecvMultishot(
        Queue& q, int fd, size_t entry_size, unsigned int flags,
        const rawstd::TraceEvent& trace_event,
        std::shared_ptr<RecvMultishotBackend> backend
    ) :
        EventSimplex(q, fd, trace_event),
        _entry_size(entry_size),
        _flags(flags),
        _backend(std::move(backend)) {}

    void dispatch() override final;

    bool is_completed() const noexcept override final { return true; }
    bool is_multishot() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventSimplexMessageRead final : public EventSimplex {
private:
    msghdr* _msg;
    unsigned int _flags;

public:
    EventSimplexMessageRead(
        Queue& q, int fd, msghdr* msg, unsigned int flags,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _msg(msg),
        _flags(flags) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return true; }
    bool is_write() const noexcept override final { return false; }

    ssize_t process() noexcept override final;
};

class EventMultiplexScalarWrite final : public EventMultiplexScalar {
public:
    EventMultiplexScalarWrite(
        Queue& q, int fd, const void* buf, size_t size,
        const rawstd::TraceEvent& trace_event
    ) :
        EventMultiplexScalar(q, fd, buf, size, trace_event) {}

    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

class EventMultiplexVectorWrite final : public EventMultiplexVector {
public:
    EventMultiplexVectorWrite(
        Queue& q, int fd, const iovec* iov, unsigned int niov,
        const rawstd::TraceEvent& trace_event
    ) :
        EventMultiplexVector(q, fd, iov, niov, trace_event) {}

    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

class EventSimplexScalarPositionalWrite final : public EventSimplex {
private:
    const void* _buf;
    size_t _size;
    off_t _offset;
    bool _sync;

public:
    EventSimplexScalarPositionalWrite(
        Queue& q, int fd, const void* buf, size_t size, off_t offset, bool sync,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _buf(buf),
        _size(size),
        _offset(offset),
        _sync(sync) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

class EventSimplexVectorPositionalWrite final : public EventSimplex {
private:
    const iovec* _iov;
    unsigned int _niov;
    off_t _offset;
    bool _sync;

public:
    EventSimplexVectorPositionalWrite(
        Queue& q, int fd, const iovec* iov, unsigned int niov, off_t offset,
        bool sync, const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _iov(iov),
        _niov(niov),
        _offset(offset),
        _sync(sync) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

class EventSimplexScalarSend final : public EventSimplex {
private:
    const void* _buf;
    size_t _size;
    unsigned int _flags;

public:
    EventSimplexScalarSend(
        Queue& q, int fd, const void* buf, size_t size, unsigned int flags,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _buf(buf),
        _size(size),
        _flags(flags) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

class EventSimplexMessageWrite final : public EventSimplex {
private:
    const msghdr* _msg;
    unsigned int _flags;

public:
    EventSimplexMessageWrite(
        Queue& q, int fd, const msghdr* msg, unsigned int flags,
        const rawstd::TraceEvent& trace_event
    ) :
        EventSimplex(q, fd, trace_event),
        _msg(msg),
        _flags(flags) {}

    bool is_completed() const noexcept override final { return true; }
    bool is_poll() const noexcept override final { return false; }
    bool is_accept() const noexcept override final { return false; }
    bool is_read() const noexcept override final { return false; }
    bool is_write() const noexcept override final { return true; }

    ssize_t process() noexcept override final;
};

} // namespace poll
} // namespace rawio

#endif // RAWIO_POLL_EVENT_HPP
