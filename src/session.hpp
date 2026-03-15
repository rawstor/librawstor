#ifndef RAWSTOR_SESSION_HPP
#define RAWSTOR_SESSION_HPP

#include "object.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/uri.hpp>

#include <rawstor/object.h>

#include <functional>
#include <memory>
#include <sstream>

namespace rawstor {

class Task;

class Session {
private:
    unsigned int _depth;
    URI _uri;
    int _fd;

protected:
    rawstor::io::Queue& _queue;

    inline void set_fd(int fd) noexcept { _fd = fd; }

public:
    static std::unique_ptr<Session>
    create(rawstor::io::Queue& queue, const URI& uri, unsigned int depth);

    Session(rawstor::io::Queue& queue, const URI& uri, unsigned int depth);
    Session(const Session&) = delete;
    Session(Session&&) noexcept = delete;
    virtual ~Session();
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    std::string str() const;

    inline const URI& uri() const noexcept { return _uri; }

    inline unsigned int depth() const noexcept { return _depth; }

    inline int fd() const noexcept { return _fd; }

    virtual void create(
        const RawstorUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) = 0;

    virtual void
    remove(const RawstorUUID& id, std::function<void(int)>&& cb) = 0;

    virtual void spec(
        const RawstorUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) = 0;

    virtual void set_object(RawstorObject* object) = 0;

    virtual void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) = 0;
};

} // namespace rawstor

#endif // RAWSTOR_SESSION_HPP
