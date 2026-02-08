#ifndef RAWSTORIO_POLL_QUEUE_HPP
#define RAWSTORIO_POLL_QUEUE_HPP

#include "poll_event.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/ringbuf.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace rawstor {
namespace io {
namespace poll {

class Event;

class Session;

class Queue final : public rawstor::io::Queue {
private:
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;
    rawstor::RingBuf<Event> _cqes;

    Session& _get_session(int fd);

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth) :
        rawstor::io::Queue(depth),
        _cqes(depth) {}

    rawstor::io::Event* poll(
        int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* poll_multishot(
        int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* read(
        int fd, void* buf, size_t size, std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* readv(
        int fd, iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* pread(
        int fd, void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* preadv(
        int fd, iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* recv(
        int fd, void* buf, size_t size, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* recv_multishot(
        int fd, size_t entry_size, unsigned int entries, unsigned int flags,
        std::unique_ptr<rawstor::io::TaskVectorExternal> t
    ) override;

    rawstor::io::Event* recvmsg(
        int fd, msghdr* msg, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* write(
        int fd, const void* buf, size_t size,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* writev(
        int fd, const iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* pwrite(
        int fd, const void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* send(
        int fd, const void* buf, size_t size, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* sendmsg(
        int fd, const msghdr* msg, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    void cancel(rawstor::io::Event* e) override;

    void wait(unsigned int timeout) override;
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_POLL_QUEUE_HPP
