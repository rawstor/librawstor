#ifndef RAWSTOR_SESSION_HPP
#define RAWSTOR_SESSION_HPP

#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <functional>
#include <list>
#include <memory>
#include <string>
#include <vector>

namespace rawstor {

class Task;

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

    virtual void list(
        unsigned int limit, const RawstdUUID& token,
        std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&&
            cb
    ) = 0;

    /*
     * Establishes the backend connection. Local backends have nothing to
     * connect and complete immediately.
     */
    virtual void connect(std::function<void(int)>&& cb) { cb(0); }

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

    /*
     * Like spec(), but reports the full per-copy record including the
     * mirror consistency state (see docs/mirroring.md).
     */
    virtual void meta(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) = 0;

    /*
     * Persists the mirror consistency state of the object durably (synced
     * to stable storage before cb fires). The size field of meta is ignored:
     * the stored size is preserved.
     */
    virtual void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    ) = 0;

    virtual void
    info(std::function<void(const RawstorLocationInfo&, int)>&& cb) = 0;

    /*
     * Enumerates every stored object with its metadata: the source of the
     * MDS reconstruct scan (CMD_LIST_CHUNKS). Unlike list(), which paginates
     * bare UUIDs for `rawstor list`, this reports the full per-copy record
     * and does so in one shot. Objects whose metadata cannot be read are
     * skipped with an error logged -- the scan salvages the readable
     * copies; an unreadable copy is unusable anyway and its chunk is
     * covered by the mirrors.
     */
    virtual void list_chunks(
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    ) = 0;

    virtual void set_object(Object* object, std::function<void(int)>&& cb) = 0;

    virtual void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void pwrite(
        const void* buf, size_t size, off_t offset, bool sync,
        std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync, std::function<void(size_t, int)>&& cb
    ) = 0;

    virtual void flush(std::function<void(int)>&& cb) = 0;
};

} // namespace rawstor

#endif // RAWSTOR_SESSION_HPP
