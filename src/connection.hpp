#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "object.hpp"

#include <rawstor/rawstor.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <functional>
#include <memory>
#include <vector>

#include <cstddef>

namespace rawstor {

class Session;

class Connection final {
private:
    struct OpenState;

    rawio::Queue& _queue;
    Object* _object;

    std::vector<std::shared_ptr<Session>> _sessions;
    size_t _session_index;

    /*
     * Expires on close()/destruction; async open/reopen completions check
     * it before touching the connection, which may be gone by then.
     */
    std::shared_ptr<int> _alive;

    /* In-flight session reopens and operations waiting for them. */
    unsigned int _reopens;
    std::vector<std::function<void(int)>> _reopen_waiters;

    /*
     * When false, failed operations are not retried through a session
     * reopen: the error surfaces to the owner. A mirrored object disables
     * transparent retries once it is DIRTY — a reopened session may talk
     * to a restarted backend that lost acknowledged writes, so the owner
     * must degrade the mirror instead (docs/mirroring.md, case F6).
     */
    bool _transparent_retry;

    static void _open_attempt(const std::shared_ptr<OpenState>& st);
    static void _open_next(const std::shared_ptr<OpenState>& st);
    static void _open_set_object(const std::shared_ptr<OpenState>& st);
    static void _open_failed(const std::shared_ptr<OpenState>& st, int error);

    void _open(
        const rawstd::URI& location, Object* object, size_t nsessions,
        std::function<void(std::vector<std::shared_ptr<Session>>&&, int)>&& cb
    );

    void
    _op(const char* func_name, size_t size, off_t offset,
        const std::shared_ptr<std::function<void(size_t, int)>>& cb,
        const std::shared_ptr<std::function<void(
            std::shared_ptr<Session>, std::function<void(size_t, int)>&&
        )>>& op,
        unsigned int attempt);

public:
    static void create(
        rawio::Queue& queue, const rawstd::URI& target,
        const RawstorObjectSpec& sp, std::function<void(int)>&& cb
    );

    static void remove(
        rawio::Queue& queue, const rawstd::URI& target,
        std::function<void(int)>&& cb
    );

    static void meta(
        rawio::Queue& queue, const rawstd::URI& target,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    );

    static void set_state(
        rawio::Queue& queue, const rawstd::URI& target,
        const RawstorObjectMeta& meta, std::function<void(int)>&& cb
    );

    /* Enumerates the objects of a location (no UUID): CMD_LIST_CHUNKS. */
    static void list(
        rawio::Queue& queue, const rawstd::URI& location,
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    );

    static void snapshot(
        rawio::Queue& queue, const rawstd::URI& target, uint64_t snap_id,
        std::function<void(int)>&& cb
    );

    static void snap_remove(
        rawio::Queue& queue, const rawstd::URI& target, uint64_t snap_id,
        std::function<void(int)>&& cb
    );

    explicit Connection(rawio::Queue& queue);
    Connection(const Connection&) = delete;
    ~Connection();

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    void invalidate_session(
        const std::shared_ptr<Session>& s, std::function<void(int)>&& cb
    );

    void set_transparent_retry(bool enabled) noexcept;

    void meta(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    );

    void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    );

    void snapshot(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    );

    void snap_remove(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    );

    const rawstd::URI* location() const noexcept;

    void open(
        const rawstd::URI& location, Object* object, size_t nsessions,
        std::function<void(int)>&& cb
    );

    void close();

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void flush(std::function<void(size_t, int)>&& cb);
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
