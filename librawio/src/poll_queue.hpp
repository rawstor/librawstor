#ifndef RAWIO_POLL_QUEUE_HPP
#define RAWIO_POLL_QUEUE_HPP

#include "poll_event.hpp"

#include <rawio/queue.hpp>

#include <rawstd/ringbuf.hpp>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawio {
namespace poll {

class Event;

class Session;

class Queue final : public rawio::Queue {
private:
    std::list<std::unique_ptr<EventEval>> _eval_sqes;
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;
    rawstd::RingBuf<Event> _cqes;

    // Every Event currently inside one of _wait_timeout()/_reap_timers()/
    // ~Queue()'s own dispatch() calls, outermost first -- a stack rather
    // than a single Event*, since dispatch()ing one Event can synchronously
    // resume a coroutine whose own control flow (e.g. a destructor running
    // as a direct consequence, itself calling back into this same Queue)
    // reenters _wait_timeout() before the outer dispatch() call has
    // returned. cancel()'s own fallback (see below) needs every level of
    // that nesting, not just the innermost one, to still recognize an
    // Event that's mid-dispatch: one whose completion has been popped off
    // _cqes/_eval_sqes for processing but not yet requeued in whatever
    // structure normally makes it findable (e.g. a multishot read's own
    // Session::read() re-registration, which only happens once its
    // dispatch() call returns).
    std::vector<Event*> _current_events;

    // timeout()'s pending timers, kept sorted ascending by deadline (see
    // EventTimer's own comment) -- deliberately not routed through _cqes,
    // which is sized for `depth` real I/O ops in flight and would ENOBUFS
    // under a caller keeping more timeout()s in flight than that.
    std::list<std::unique_ptr<EventTimer>> _timers;

    /*
     * Bumped once per ::poll() readiness batch. Mirrors the uring
     * backend's _dispatch_generation: lets multishot poll events collapse
     * same-batch duplicate wakeups into a single callback invocation, so
     * both backends give callers (e.g. an eventfd drain that can hit
     * EAGAIN if invoked twice for one accumulated write) the same
     * at-most-once-per-batch guarantee.
     */
    unsigned int _dispatch_generation;

    Session& _get_session(int fd);

    void _wait_timeout(int msec);

    // Dispatches every EventTimer in _timers whose deadline has already
    // passed (as of one now() read at entry) and returns whether it
    // dispatched anything -- called both ahead of _eval_sqes/before ever
    // blocking in ::poll() (so a timer that's already due resolves without
    // blocking, exactly like an EventEval) and right after every ::poll()
    // return inside _wait_timeout()'s loop.
    bool _reap_timers();

    void _eval(std::unique_ptr<EventEval> event);

protected:
    void _attach(
        rawio::Event* event, std::coroutine_handle<> h, size_t* value,
        int* error
    ) noexcept override;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth) :
        rawio::Queue(depth),
        _cqes(depth),
        _dispatch_generation(0) {}

    ~Queue() override;

    inline unsigned int dispatch_generation() const noexcept {
        return _dispatch_generation;
    }

    rawio::Awaitable<int>
    open(const char* path, int flags, mode_t mode) override;

    rawio::Awaitable<int> close(int fd) override;

    rawio::Awaitable<int> poll(int fd, unsigned int mask) override;

    rawio::PollStream poll_multishot(int fd, unsigned int mask) override;

    rawio::Awaitable<int>
    accept(int fd, sockaddr* addr, socklen_t* addrlen) override;

    rawio::AcceptStream accept_multishot(int fd) override;

    rawio::Awaitable<int>
    connect(int fd, const sockaddr* addr, socklen_t addrlen) override;

    rawio::Awaitable<size_t> read(int fd, void* buf, size_t size) override;

    rawio::Awaitable<size_t>
    readv(int fd, iovec* iov, unsigned int niov) override;

    rawio::Awaitable<size_t>
    pread(int fd, void* buf, size_t size, off_t offset) override;

    rawio::Awaitable<size_t>
    preadv(int fd, iovec* iov, unsigned int niov, off_t offset) override;

    rawio::Awaitable<size_t>
    recv(int fd, void* buf, size_t size, unsigned int flags) override;

    rawio::RecvStream recv_multishot(
        int fd, size_t entry_size, unsigned int entries, size_t size,
        unsigned int flags
    ) override;

    rawio::Awaitable<size_t>
    recvmsg(int fd, msghdr* msg, unsigned int flags) override;

    rawio::Awaitable<size_t>
    write(int fd, const void* buf, size_t size) override;

    rawio::Awaitable<size_t>
    writev(int fd, const iovec* iov, unsigned int niov) override;

    rawio::Awaitable<size_t> pwrite(
        int fd, const void* buf, size_t size, off_t offset, bool sync
    ) override;

    rawio::Awaitable<size_t> pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset, bool sync
    ) override;

    rawio::Awaitable<int> fsync(int fd, bool datasync) override;

    rawio::Awaitable<int> stat(const char* path, struct stat* buf) override;

    rawio::Awaitable<int>
    fallocate(int fd, int mode, off_t offset, off_t len) override;

    rawio::Awaitable<size_t>
    send(int fd, const void* buf, size_t size, unsigned int flags) override;

    rawio::Awaitable<size_t>
    sendmsg(int fd, const msghdr* msg, unsigned int flags) override;

    rawio::Awaitable<void> timeout(unsigned int usec) override;

    rawio::Awaitable<void> cancel(rawio::Event* e) override;

    rawio::Awaitable<void> cancel(int fd) override;

    void wait() override;

    void wait_timeout(unsigned int msec) override;
};

} // namespace poll
} // namespace rawio

#endif // RAWIO_POLL_QUEUE_HPP
