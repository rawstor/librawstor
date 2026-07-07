#ifndef RAWSTOR_SESSION_HPP
#define RAWSTOR_SESSION_HPP

#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <rawstor/object.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace rawstor {

class Task;

class Session {
private:
    rawstd::URI _location;
    int _fd;

protected:
    rawio::Queue& _queue;

    inline void set_fd(int fd) noexcept { _fd = fd; }

public:
    static std::unique_ptr<Session>
    create(rawio::Queue& queue, const rawstd::URI& location);

    Session(rawio::Queue& queue, const rawstd::URI& location);
    Session(const Session&) = delete;
    Session(Session&&) noexcept = delete;
    virtual ~Session();
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    std::string str() const;

    inline const rawstd::URI& location() const noexcept { return _location; }

    inline int fd() const noexcept { return _fd; }

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

    /*
     * Queries the copy metadata of one version of the object: snap = 0 is
     * the live copy, anything else an immutable snapshot version (its
     * consistency-state fields are frozen at snapshot time; size is what
     * matters). ENOTSUP for snapshots on backends without CoW.
     */
    virtual void meta(
        const RawstdUUID& id, uint64_t snap,
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

    /*
     * Enumerates every stored object with its metadata: the source of the
     * MDS reconstruct scan (CMD_LIST_CHUNKS). Objects whose metadata cannot
     * be read are skipped with an error logged — the scan salvages the
     * readable copies; an unreadable copy is unusable anyway and its chunk
     * is covered by the mirrors.
     */
    virtual void list(
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    ) = 0;

    /*
     * Native CoW snapshot of the object as version snap_id (never 0 — 0 is
     * the live version). The caller owns crash consistency: all
     * acknowledged writes must be flushed before the call. ENOTSUP on
     * backends without CoW — never a fallback copy behind the caller's
     * back (rawstor_docs/Mds.md, "Snapshots").
     */
    virtual void snapshot(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) = 0;

    virtual void snap_remove(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) = 0;

    virtual void set_object(Object* object, std::function<void(int)>&& cb) = 0;

    /*
     * Syncs completed writes of the bound object to stable storage. The
     * default implementation runs fdatasync(fd()) in a worker thread.
     */
    virtual void flush(std::function<void(size_t, int)>&& cb);

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
