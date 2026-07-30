#ifndef RAWIO_POLL_QUEUE_HPP
#define RAWIO_POLL_QUEUE_HPP

#include "poll_event.hpp"

#include <rawio/queue.hpp>

#include <rawstd/ringbuf.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace rawio {
namespace poll {

class Event;

class Session;

class Queue final : public rawio::Queue {
private:
    std::list<std::unique_ptr<EventEval>> _eval_sqes;
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;
    rawstd::RingBuf<Event> _cqes;
    Event* _current_event;

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

    void _wait_timeout(int timeout);

    void _eval(std::unique_ptr<EventEval>&& event);

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth) :
        rawio::Queue(depth),
        _cqes(depth),
        _current_event(nullptr),
        _dispatch_generation(0) {}

    inline unsigned int dispatch_generation() const noexcept {
        return _dispatch_generation;
    }

    rawio::Event* open(
        const char* path, int flags, mode_t mode, std::function<void(int)>&& cb
    ) override;

    rawio::Event* close(int fd, std::function<void(int)>&& cb) override;

    rawio::Event*
    poll(int fd, unsigned int mask, std::function<void(int)>&& cb) override;

    rawio::Event* poll_multishot(
        int fd, unsigned int mask, std::function<void(int)>&& cb
    ) override;

    rawio::Event* accept(
        int fd, sockaddr* addr, socklen_t* addrlen,
        std::function<void(int)>&& cb
    ) override;

    rawio::Event*
    accept_multishot(int fd, std::function<void(int)>&& cb) override;

    rawio::Event* connect(
        int fd, const sockaddr* addr, socklen_t addrlen,
        std::function<void(int)>&& cb
    ) override;

    rawio::Event* read(
        int fd, void* buf, size_t size, std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* readv(
        int fd, iovec* iov, unsigned int niov,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* pread(
        int fd, void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* preadv(
        int fd, iovec* iov, unsigned int niov, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* recv(
        int fd, void* buf, size_t size, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* recv_multishot(
        int fd, size_t entry_size, unsigned int entries, size_t size,
        unsigned int flags,
        std::function<size_t(const iovec*, unsigned int, size_t, int)>&& cb
    ) override;

    rawio::Event* recvmsg(
        int fd, msghdr* msg, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* write(
        int fd, const void* buf, size_t size,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* writev(
        int fd, const iovec* iov, unsigned int niov,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* pwrite(
        int fd, const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* send(
        int fd, const void* buf, size_t size, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* sendmsg(
        int fd, const msghdr* msg, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    void cancel(rawio::Event* e) override;

    void cancel(int fd) override;

    void wait() override;

    void wait_timeout(unsigned int timeout) override;
};

} // namespace poll
} // namespace rawio

#endif // RAWIO_POLL_QUEUE_HPP
