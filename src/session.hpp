#ifndef RAWSTOR_SESSION_HPP
#define RAWSTOR_SESSION_HPP

#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <memory>
#include <string>
#include <vector>

namespace rawstor {

class Session : public std::enable_shared_from_this<Session> {
private:
    rawstd::URI _location;
    int _fd;

protected:
    struct Private {
        explicit Private() = default;
    };

    rawio::Queue& _queue;

    inline void set_fd(int fd) noexcept { _fd = fd; }

public:
    static std::unique_ptr<Session>
    create(rawio::Queue& queue, const rawstd::URI& location);

    Session(Private, rawio::Queue& queue, const rawstd::URI& location);
    Session(const Session&) = delete;
    Session(Session&&) noexcept = delete;
    virtual ~Session();
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    std::string str() const;

    inline const rawstd::URI& location() const noexcept { return _location; }

    inline int fd() const noexcept { return _fd; }

    // `next_token` is written on success (pagination cursor for the
    // following call); `token` is this call's own cursor, unchanged by
    // the callee.
    virtual rawstd::Task<std::vector<RawstdUUID>> list(
        unsigned int limit, const RawstdUUID& token, RawstdUUID& next_token
    ) = 0;

    virtual rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) = 0;

    virtual rawstd::Task<void> remove(const RawstdUUID& id) = 0;

    virtual rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) = 0;

    virtual rawstd::Task<RawstorLocationInfo> info() = 0;

    virtual void set_object(Object* object) = 0;

    virtual rawstd::Task<size_t>
    pread(void* buf, size_t size, off_t offset) = 0;

    virtual rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) = 0;

    virtual rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) = 0;

    virtual rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) = 0;

    virtual rawstd::Task<void> flush() = 0;
};

} // namespace rawstor

#endif // RAWSTOR_SESSION_HPP
