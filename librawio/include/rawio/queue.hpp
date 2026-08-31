#ifndef RAWIO_QUEUE_HPP
#define RAWIO_QUEUE_HPP

#include <coroutine>
#include <memory>
#include <string>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

struct RawIOQueue {};

// Forward-declared rather than pulled in via <sys/stat.h>: this header
// stays buildable on platforms (e.g. macOS) that don't define struct
// statx at all -- only a pointer to it appears below, never dereferenced
// here. Backends that actually implement statx() include <sys/stat.h>
// themselves.
struct statx;

namespace rawio {

typedef void Event;

template <typename T>
class Awaitable;

class PollStream;
class AcceptStream;
class RecvStream;

class Queue : public RawIOQueue {
    // Awaitable<T>::await_suspend() is the only caller of the protected
    // _attach() hook below; see <rawio/awaitable.hpp>.
    template <typename T>
    friend class Awaitable;

private:
    unsigned int _depth;

protected:
    // The single hook every backend implements to make Awaitable<T>
    // backend-agnostic (Awaitable<T> itself is a concrete, non-virtual
    // template shared by every backend -- C++ virtual overrides require
    // identical return types, so a bespoke per-backend awaitable isn't an
    // option). Called exactly once per Awaitable<T>, from
    // Awaitable<T>::await_suspend(), i.e. always before the next
    // wait()/wait_timeout() call. `value`/`error` point into the (still
    // alive -- see Awaitable<T>'s class comment) awaitable itself; the
    // backend writes the outcome into them and resumes `h` once the
    // operation completes.
    virtual void _attach(
        Event* event, std::coroutine_handle<> h, size_t* value, int* error
    ) noexcept = 0;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);
    static std::unique_ptr<Queue> create(unsigned int depth);

    explicit Queue(unsigned int depth);
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;
    virtual ~Queue() = default;
    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;

    inline unsigned int depth() const noexcept { return _depth; }

    virtual Awaitable<int> open(const char* path, int flags, mode_t mode) = 0;

    virtual Awaitable<int> close(int fd) = 0;

    virtual Awaitable<int> poll(int fd, unsigned int mask) = 0;

    virtual PollStream poll_multishot(int fd, unsigned int mask) = 0;

    virtual Awaitable<int>
    accept(int fd, sockaddr* addr, socklen_t* addrlen) = 0;

    virtual AcceptStream accept_multishot(int fd) = 0;

    virtual Awaitable<int>
    connect(int fd, const sockaddr* addr, socklen_t addrlen) = 0;

    virtual Awaitable<size_t> read(int fd, void* buf, size_t size) = 0;

    virtual Awaitable<size_t> readv(int fd, iovec* iov, unsigned int niov) = 0;

    virtual Awaitable<size_t>
    pread(int fd, void* buf, size_t size, off_t offset) = 0;

    virtual Awaitable<size_t>
    preadv(int fd, iovec* iov, unsigned int niov, off_t offset) = 0;

    virtual Awaitable<size_t>
    recv(int fd, void* buf, size_t size, unsigned int flags) = 0;

    /**
     * entry_size: must be a power of two.
     * entries: must be a power of two.
     */
    virtual RecvStream recv_multishot(
        int fd, size_t entry_size, unsigned int entries, size_t size,
        unsigned int flags
    ) = 0;

    virtual Awaitable<size_t>
    recvmsg(int fd, msghdr* msg, unsigned int flags) = 0;

    virtual Awaitable<size_t> write(int fd, const void* buf, size_t size) = 0;

    virtual Awaitable<size_t>
    writev(int fd, const iovec* iov, unsigned int niov) = 0;

    virtual Awaitable<size_t>
    pwrite(int fd, const void* buf, size_t size, off_t offset, bool sync) = 0;

    virtual Awaitable<size_t> pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset, bool sync
    ) = 0;

    virtual Awaitable<int> fsync(int fd, bool datasync) = 0;

    // Thin async wrapper over statx(2); `dirfd`/`path`/`flags`/`mask`/`buf`
    // are passed through unmodified, so callers stay in charge of e.g.
    // AT_EMPTY_PATH-style fstat-by-fd vs. path-relative lookups and of
    // which STATX_* fields they actually need.
    virtual Awaitable<int> statx(
        int dirfd, const char* path, int flags, unsigned int mask,
        struct statx* buf
    ) = 0;

    // fd-local space-management hint/op (hole-punch, zero-range, plain
    // preallocation, ...) -- `mode` is the raw fallocate(2) FALLOC_FL_*
    // bitmask, passed through unmodified so callers stay in charge of
    // which specific operation this is; see blk::Session::discard()/
    // write_zeroes() (src/blk_session.cpp) for the only caller today.
    virtual Awaitable<int>
    fallocate(int fd, int mode, off_t offset, off_t len) = 0;

    virtual Awaitable<size_t>
    send(int fd, const void* buf, size_t size, unsigned int flags) = 0;

    virtual Awaitable<size_t>
    sendmsg(int fd, const msghdr* msg, unsigned int flags) = 0;

    // A standalone timer, not tied to any fd: resolves successfully once
    // `usec` microseconds have elapsed. Submission already happens before
    // this returns, exactly like every op above -- the clock starts now,
    // not whenever the caller next gets around to co_await-ing the
    // returned Awaitable<void> (or calling wait()/wait_timeout() at all).
    // Cancelling it via cancel(Event*) is the only way it surfaces an
    // exception, exactly like every other op: ECANCELED if cancelled
    // before firing.
    virtual Awaitable<void> timeout(unsigned int usec) = 0;

    // Requests cancellation; submission already happens before this
    // returns, exactly like every op above -- awaiting the result is
    // optional. Discarding the returned Awaitable<void> (the common case,
    // e.g. from a destructor, which can't co_await anything) is a safe,
    // ordinary fire-and-forget cancellation. Awaiting it only tells you
    // the cancellation request itself has been fully processed -- it
    // never reports whether the target was actually found, and it never
    // throws for that reason (ENOENT/EALREADY are ordinary outcomes here, not
    // failures). The target operation's own eventual completion
    // (ECANCELED, or its natural result if the cancellation lost the
    // race) is the only place that outcome is observable.
    virtual Awaitable<void> cancel(Event* event) = 0;

    virtual Awaitable<void> cancel(int fd) = 0;

    virtual void wait() = 0;

    virtual void wait_timeout(unsigned int msec) = 0;
};

} // namespace rawio

#endif // RAWIO_QUEUE_HPP
