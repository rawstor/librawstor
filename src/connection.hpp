#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <vector>

#include <cstddef>

namespace rawstor {

class Task;

class Session;

class Connection final {
private:
    RawstorObject* _object;
    unsigned int _depth;

    std::vector<std::shared_ptr<Session>> _sessions;
    size_t _session_index;

    std::vector<std::shared_ptr<Session>>
    _open(const URI& uri, RawstorObject* object, size_t nsessions);

public:
    Connection(unsigned int depth);
    Connection(const Connection&) = delete;
    ~Connection();

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    void invalidate_session(const std::shared_ptr<Session>& s);

    const URI* uri() const noexcept;

    void create(
        rawstor::io::Queue& queue, const URI& uri, const RawstorObjectSpec& sp,
        std::unique_ptr<Task> t
    );

    void
    remove(rawstor::io::Queue& queue, const URI& uri, std::unique_ptr<Task> t);

    void spec(
        rawstor::io::Queue& queue, const URI& uri, RawstorObjectSpec* sp,
        std::unique_ptr<Task> t
    );

    void open(const URI& uri, RawstorObject* object, size_t nsessions);

    void close();

    void pread(void* buf, size_t size, off_t offset, std::unique_ptr<Task> t);

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::unique_ptr<Task> t
    );

    void
    pwrite(const void* buf, size_t size, off_t offset, std::unique_ptr<Task> t);

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::unique_ptr<Task> t
    );
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
