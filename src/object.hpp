#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <functional>
#include <memory>
#include <vector>

struct RawstorObject {};

namespace rawstor {

class Connection;

class Object final : public RawstorObject {
private:
    struct OpenState;

    enum class MirrorState { IN_SYNC, STALE };

    /*
     * A reachable arm of the mirror set. Arms that could not be opened are
     * not represented: the difference between _nmirrors and _mirrors.size()
     * is the number of unreachable arms.
     */
    struct Mirror {
        std::unique_ptr<rawstor::Connection> cn;
        MirrorState state;
        RawstorObjectMeta meta;
    };

    rawio::Queue& _queue;
    RawstdUUID _id;

    /* Configured mirror width N (the target list length). */
    size_t _nmirrors;
    std::vector<Mirror> _mirrors;

    /* DIRTY has been durably recorded on the in-sync arms. */
    bool _dirty;

    /* Survivors dropped to <= N/2 (N >= 3): writes fail until recovery. */
    bool _writes_frozen;

    /*
     * A metadata barrier (dirty gate or degrade) is in flight; operations
     * that depend on the recorded state park in _meta_waiters and are
     * drained once the barrier settles.
     */
    bool _meta_op_running;
    std::vector<std::function<void()>> _meta_waiters;

    /* Arms marked STALE whose exclusion is not yet durably recorded. */
    size_t _unrecorded_stale;

    /* Current sync-set identity adopted at open / last barrier. */
    uint64_t _epoch;
    uint64_t _sync_id;
    uint64_t _sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];

    /*
     * Expires on destruction. Detached background work (read-repair, the
     * degrade barriers it may trigger) checks it before touching the
     * object: unlike caller I/O, such work is not covered by the "no I/O
     * in flight at close" contract.
     */
    std::shared_ptr<int> _alive;

    Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);

    void _open_next(const std::shared_ptr<OpenState>& st);
    void _open_meta_next(const std::shared_ptr<OpenState>& st);
    void _open_analyze(const std::shared_ptr<OpenState>& st);

    size_t _in_sync_count() const noexcept;
    bool _below_write_quorum(size_t survivors) const noexcept;

    void _settle_meta(std::function<void()>&& cont);
    void _with_dirty(std::function<void(int)>&& cont);
    void _run_dirty_barrier(std::function<void(int)>&& done);
    void _degrade(std::vector<size_t>&& idxs, std::function<void(int)>&& done);
    void _run_degrade_barrier(std::function<void(int)>&& done);
    void _run_meta_fan_out(
        const RawstorObjectMeta& meta, std::function<void(int)>&& done
    );
    void _finish_meta_op();

    void _fan_out_write(
        std::function<void(Connection&, std::function<void(size_t, int)>&&)>&&
            issue,
        std::function<void(size_t, int)>&& cb
    );

    struct ReadState;
    void _read_attempt(const std::shared_ptr<ReadState>& st);
    void _read_settle(const std::shared_ptr<ReadState>& st, size_t result);
    void _read_repair(size_t idx, off_t offset, std::vector<char>&& data);

    void _teardown(std::function<void(int)>&& cb, int error);

public:
    static void open(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        std::function<void(Object*, int)>&& cb
    );

    static void create(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        const RawstorObjectSpec& sp, std::function<void(int)>&& cb
    );
    static void remove(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        std::function<void(int)>&& cb
    );
    static void spec(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        RawstorObjectSpec* sp, std::function<void(int)>&& cb
    );
    static void meta(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        RawstorObjectMeta* meta, std::function<void(int)>&& cb
    );
    static void set_state(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        const RawstorObjectMeta& meta, std::function<void(int)>&& cb
    );

    static void create(
        const std::vector<rawstd::URI>& targets, const RawstorObjectSpec& sp
    );
    static void remove(const std::vector<rawstd::URI>& targets);
    static void
    spec(const std::vector<rawstd::URI>& targets, RawstorObjectSpec* sp);
    static void
    meta(const std::vector<rawstd::URI>& targets, RawstorObjectMeta* meta);
    static void set_state(
        const std::vector<rawstd::URI>& targets, const RawstorObjectMeta& meta
    );

    Object(const Object&) = delete;
    Object(Object&&) = delete;
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    std::vector<rawstd::URI> locations() const;

    inline const RawstdUUID& id() const noexcept { return _id; }

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

    /*
     * Clean close: flushes data and durably marks the in-sync arms CLEAN,
     * then destroys the object. On any error the affected arms are left
     * DIRTY (the safe direction) and the object is destroyed anyway; the
     * first error is reported.
     */
    void close(std::function<void(int)>&& cb);
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
