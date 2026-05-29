#ifndef RAWSTOR_SESSION_HPP
#define RAWSTOR_SESSION_HPP

#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <rawstor/object.h>

#include <functional>
#include <memory>
#include <string>

namespace rawstor {

class Task;

class Session {
private:
    unsigned int _depth;
    rawstd::URI _location;
    int _fd;

protected:
    rawio::Queue& _queue;

    inline void set_fd(int fd) noexcept { _fd = fd; }

public:
    static std::unique_ptr<Session> create(
        rawio::Queue& queue, const rawstd::URI& location, unsigned int depth
    );

    Session(
        rawio::Queue& queue, const rawstd::URI& location, unsigned int depth
    );
    Session(const Session&) = delete;
    Session(Session&&) noexcept = delete;
    virtual ~Session();
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    std::string str() const;

    inline const rawstd::URI& location() const noexcept { return _location; }

    inline unsigned int depth() const noexcept { return _depth; }

    inline int fd() const noexcept { return _fd; }

    virtual void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) = 0;

    virtual void
    remove(const RawstdUUID& id, std::function<void(int)>&& cb) = 0;

    virtual void spec(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) = 0;

    virtual void set_object(Object* object) = 0;

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
