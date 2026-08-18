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
    // Set by a subclass's destructor, before it starts tearing itself
    // down, to true. A completion delivered during that teardown (e.g.
    // uring::Queue::~Queue() synchronously resuming every still-pending
    // op with ECANCELED) can release the last shared_ptr keeping some
    // unrelated object alive, whose own destructor calls back into
    // cancel() on this same, still-destructing Queue. cancel() checks this
    // flag and becomes a safe no-op in that case: the Queue is going away
    // regardless, so there is nothing left to cancel.
    bool _tearing_down = false;

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

    virtual Awaitable<size_t>
    send(int fd, const void* buf, size_t size, unsigned int flags) = 0;

    virtual Awaitable<size_t>
    sendmsg(int fd, const msghdr* msg, unsigned int flags) = 0;

    virtual void cancel(Event* event) = 0;

    virtual void cancel(int fd) = 0;

    virtual void wait() = 0;

    virtual void wait_timeout(unsigned int timeout) = 0;
};

} // namespace rawio

#endif // RAWIO_QUEUE_HPP
