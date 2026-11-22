#ifndef RAWIO_STREAM_HPP
#define RAWIO_STREAM_HPP

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>

#include <sys/uio.h>

#include <coroutine>
#include <memory>
#include <vector>

namespace rawio {

/**
 * co_await-able handle for poll_multishot(): `while (int revents =
 * co_await stream.next()) { ... }` -- next() throws std::system_error on
 * any error, including ECANCELED once cancel()-ed, so a plain loop
 * naturally ends via that exception rather than a sentinel value.
 */
class PollStream final {
public:
    // Must stay public: implemented by backend-specific classes outside
    // this header (e.g. rawio::PollStream::Backend is a base class named
    // from uring_queue.cpp/poll_event.hpp).
    class Backend {
    public:
        virtual ~Backend() = default;

        // Non-blocking attempt to produce the next item from an
        // already-arrived batch of data: returns true with `out`/`error`
        // filled in (`error == 0` means `out` holds a real item; nonzero
        // means the awaiting co_await should throw it), or false --
        // nothing ready yet, the caller must suspend and wait to be
        // resumed via set_waiter() below.
        virtual bool try_produce(int& out, int& error) noexcept = 0;
        virtual void set_waiter(
            std::coroutine_handle<> h, int* out, int* error
        ) noexcept = 0;
        virtual void close() noexcept = 0;
        virtual rawio::Event* event() const noexcept = 0;
    };

    class Next {
    private:
        Backend* _backend;
        int _value;
        int _error;

    public:
        explicit Next(Backend* backend) noexcept :
            _backend(backend),
            _value(0),
            _error(0) {}

        bool await_ready() noexcept {
            return _backend->try_produce(_value, _error);
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            _backend->set_waiter(h, &_value, &_error);
        }

        int await_resume() {
            if (_error) {
                RAWSTD_THROW_SYSTEM_ERROR(_error);
            }
            return _value;
        }
    };

private:
    std::shared_ptr<Backend> _backend;

public:
    PollStream() noexcept = default;
    explicit PollStream(std::shared_ptr<Backend> backend) noexcept :
        _backend(std::move(backend)) {}
    PollStream(const PollStream&) = delete;
    PollStream& operator=(const PollStream&) = delete;
    PollStream(PollStream&&) noexcept = default;
    PollStream& operator=(PollStream&&) noexcept = default;
    ~PollStream() { close(); }

    Next next() noexcept { return Next(_backend.get()); }

    void close() noexcept {
        if (_backend) {
            _backend->close();
        }
    }

    Event* event() const noexcept {
        return _backend ? _backend->event() : nullptr;
    }
};

/**
 * co_await-able handle for accept_multishot(): same shape as PollStream,
 * `co_await stream.next()` yields the accepted fd or throws.
 */
class AcceptStream final {
public:
    // Must stay public: implemented by backend-specific classes outside
    // this header (e.g. rawio::AcceptStream::Backend is a base class named
    // from uring_queue.cpp/poll_event.hpp).
    class Backend {
    public:
        virtual ~Backend() = default;

        // Non-blocking attempt to produce the next item from an
        // already-arrived batch of data: returns true with `out`/`error`
        // filled in (`error == 0` means `out` holds a real item; nonzero
        // means the awaiting co_await should throw it), or false --
        // nothing ready yet, the caller must suspend and wait to be
        // resumed via set_waiter() below.
        virtual bool try_produce(int& out, int& error) noexcept = 0;
        virtual void set_waiter(
            std::coroutine_handle<> h, int* out, int* error
        ) noexcept = 0;
        virtual void close() noexcept = 0;
        virtual rawio::Event* event() const noexcept = 0;
    };

    class Next {
    private:
        Backend* _backend;
        int _value;
        int _error;

    public:
        explicit Next(Backend* backend) noexcept :
            _backend(backend),
            _value(0),
            _error(0) {}

        bool await_ready() noexcept {
            return _backend->try_produce(_value, _error);
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            _backend->set_waiter(h, &_value, &_error);
        }

        int await_resume() {
            if (_error) {
                RAWSTD_THROW_SYSTEM_ERROR(_error);
            }
            return _value;
        }
    };

private:
    std::shared_ptr<Backend> _backend;

public:
    AcceptStream() noexcept = default;
    explicit AcceptStream(std::shared_ptr<Backend> backend) noexcept :
        _backend(std::move(backend)) {}
    AcceptStream(const AcceptStream&) = delete;
    AcceptStream& operator=(const AcceptStream&) = delete;
    AcceptStream(AcceptStream&&) noexcept = default;
    AcceptStream& operator=(AcceptStream&&) noexcept = default;
    ~AcceptStream() { close(); }

    Next next() noexcept { return Next(_backend.get()); }

    void close() noexcept {
        if (_backend) {
            _backend->close();
        }
    }

    Event* event() const noexcept {
        return _backend ? _backend->event() : nullptr;
    }
};

/**
 * co_await-able handle for timeout_multishot(): same shape as PollStream/
 * AcceptStream, except the delivered value carries no meaning -- every
 * tick looks the same, so `while (true) { co_await stream.next(); ... }`
 * is the whole loop. next() throws std::system_error on any error,
 * including ECANCELED once cancel()-ed.
 */
class TimeoutStream final {
public:
    // Must stay public: implemented by backend-specific classes outside
    // this header (e.g. rawio::TimeoutStream::Backend is a base class
    // named from uring_queue.cpp/poll_event.hpp).
    class Backend {
    public:
        virtual ~Backend() = default;

        // Non-blocking attempt to produce the next item from an
        // already-arrived batch of data: returns true with `out`/`error`
        // filled in (`error == 0` means `out` holds a real item; nonzero
        // means the awaiting co_await should throw it), or false --
        // nothing ready yet, the caller must suspend and wait to be
        // resumed via set_waiter() below.
        virtual bool try_produce(int& out, int& error) noexcept = 0;
        virtual void set_waiter(
            std::coroutine_handle<> h, int* out, int* error
        ) noexcept = 0;
        virtual void close() noexcept = 0;
        virtual rawio::Event* event() const noexcept = 0;
    };

    class Next {
    private:
        Backend* _backend;
        int _value;
        int _error;

    public:
        explicit Next(Backend* backend) noexcept :
            _backend(backend),
            _value(0),
            _error(0) {}

        bool await_ready() noexcept {
            return _backend->try_produce(_value, _error);
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            _backend->set_waiter(h, &_value, &_error);
        }

        int await_resume() {
            if (_error) {
                RAWSTD_THROW_SYSTEM_ERROR(_error);
            }
            return _value;
        }
    };

private:
    std::shared_ptr<Backend> _backend;

public:
    TimeoutStream() noexcept = default;
    explicit TimeoutStream(std::shared_ptr<Backend> backend) noexcept :
        _backend(std::move(backend)) {}
    TimeoutStream(const TimeoutStream&) = delete;
    TimeoutStream& operator=(const TimeoutStream&) = delete;
    TimeoutStream(TimeoutStream&&) noexcept = default;
    TimeoutStream& operator=(TimeoutStream&&) noexcept = default;
    ~TimeoutStream() { close(); }

    Next next() noexcept { return Next(_backend.get()); }

    void close() noexcept {
        if (_backend) {
            _backend->close();
        }
    }

    Event* event() const noexcept {
        return _backend ? _backend->event() : nullptr;
    }
};

/**
 * co_await-able handle for recv_multishot(): `Item i = co_await
 * stream.next(want);` -- `want` is a "how many bytes am I ready to accept
 * next" flow-control value, throws std::system_error once the stream
 * ends (cancelled, EPIPE, ...),
 * possibly *after* one final successful next() call if a terminal error
 * arrived bundled with trailing data (never silently drops bytes).
 *
 * A ring that runs out of buffers does not end the stream: what the kernel
 * could not take stays in the socket, and the stream takes it as items are
 * released. Only a `want` that is more than the whole ring can hold ends it,
 * with ENOBUFS, after the last of what fits.
 */
class RecvStream final {
public:
    // Scatter-gather view into backend-owned buffers, kept alive for as
    // long as this item exists (the owning handle is type-erased so this
    // class stays backend-agnostic) -- iov()'s result is only valid for
    // as long as this item is kept alive, so read it out before letting
    // the item go.
    class Item {
    private:
        std::vector<iovec> _iov;
        size_t _size;
        std::shared_ptr<void> _owner;

    public:
        Item() noexcept : _iov(), _size(0), _owner() {}
        Item(
            std::vector<iovec> iov, size_t size, std::shared_ptr<void> owner
        ) noexcept :
            _iov(std::move(iov)),
            _size(size),
            _owner(std::move(owner)) {}
        Item(const Item&) = delete;
        Item& operator=(const Item&) = delete;
        Item(Item&&) noexcept = default;
        Item& operator=(Item&&) noexcept = default;

        const iovec* iov() const noexcept { return _iov.data(); }
        unsigned int niov() const noexcept {
            return static_cast<unsigned int>(_iov.size());
        }
        size_t size() const noexcept { return _size; }
    };

    // Must stay public: implemented by backend-specific classes outside
    // this header (e.g. rawio::RecvStream::Backend is a base class named
    // from uring_buffer.hpp/poll_event.hpp).
    class Backend {
    public:
        virtual ~Backend() = default;

        // Non-blocking attempt to produce the next item from an
        // already-arrived batch of data: returns true with `out`/`error`
        // filled in (`error == 0` means `out` holds a real item; nonzero
        // means the awaiting co_await should throw it), or false --
        // nothing ready yet, the caller must suspend and wait to be
        // resumed via set_waiter() below.
        virtual bool
        try_produce(size_t want, Item& out, int& error) noexcept = 0;
        virtual void set_waiter(
            std::coroutine_handle<> h, size_t want, Item* out, int* error
        ) noexcept = 0;
        virtual void close() noexcept = 0;
        // Requests the end of the stream, see RecvStream::cancel().
        virtual void cancel() noexcept = 0;
        virtual rawio::Event* event() const noexcept = 0;
    };

    // RecvStream::cancel() for code that does not hold the stream: the
    // stream's owner is in a coroutine, and whoever wants it stopped is
    // elsewhere. Unlike event(), it is safe to use at any time: after the
    // stream has ended, and after it was destroyed.
    class Canceller final {
    private:
        std::weak_ptr<Backend> _backend;

    public:
        Canceller() noexcept = default;
        explicit Canceller(std::weak_ptr<Backend> backend) noexcept :
            _backend(std::move(backend)) {}

        void cancel() const noexcept {
            if (std::shared_ptr<Backend> backend = _backend.lock()) {
                backend->cancel();
            }
        }
    };

    class Next {
    private:
        Backend* _backend;
        size_t _want;
        Item _item;
        int _error;

    public:
        Next(Backend* backend, size_t want) noexcept :
            _backend(backend),
            _want(want),
            _item(),
            _error(0) {}

        bool await_ready() noexcept {
            return _backend->try_produce(_want, _item, _error);
        }

        void await_suspend(std::coroutine_handle<> h) noexcept {
            _backend->set_waiter(h, _want, &_item, &_error);
        }

        Item await_resume() {
            if (_error) {
                RAWSTD_THROW_SYSTEM_ERROR(_error);
            }
            return std::move(_item);
        }
    };

private:
    std::shared_ptr<Backend> _backend;

public:
    RecvStream() noexcept = default;
    explicit RecvStream(std::shared_ptr<Backend> backend) noexcept :
        _backend(std::move(backend)) {}
    RecvStream(const RecvStream&) = delete;
    RecvStream& operator=(const RecvStream&) = delete;
    RecvStream(RecvStream&&) noexcept = default;
    RecvStream& operator=(RecvStream&&) noexcept = default;
    ~RecvStream() { close(); }

    Next next(size_t want) noexcept { return Next(_backend.get(), want); }

    void close() noexcept {
        if (_backend) {
            _backend->close();
        }
    }

    // Asks the stream to end: a pending or later next() fails with
    // ECANCELED once what already arrived is delivered. Like Queue::cancel()
    // it only requests the cancellation, and unlike close() it leaves the
    // stream usable for reading that outcome. Does nothing if the stream has
    // already ended.
    void cancel() noexcept {
        if (_backend) {
            _backend->cancel();
        }
    }

    Canceller canceller() const noexcept { return Canceller(_backend); }

    Event* event() const noexcept {
        return _backend ? _backend->event() : nullptr;
    }
};

} // namespace rawio

#endif // RAWIO_STREAM_HPP
