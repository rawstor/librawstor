#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <functional>
#include <memory>
#include <vector>

/*
 * The C-API object handle: an abstract interface with two
 * implementations — rawstor::Object (a plain, possibly mirrored object)
 * and rawstor::Volume (an MDS-backed chunked volume routing I/O onto
 * per-chunk objects).
 */
struct RawstorObject {
    virtual ~RawstorObject() = default;

    virtual const RawstdUUID& id() const noexcept = 0;

    virtual std::vector<rawstd::URI> locations() const = 0;

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

    virtual void flush(std::function<void(size_t, int)>&& cb) = 0;

    /* Clean close, then self-destruction; see rawstor::Object::close. */
    virtual void close(std::function<void(int)>&& cb) = 0;
};

namespace rawstor {

class Connection;

class Object final : public RawstorObject {
private:
    struct OpenState;
    struct ResyncState;

    /*
     * IN_SYNC - the member carries every acknowledged write; serves I/O.
     * STALE   - the member is excluded (unreachable, degraded or behind).
     * SYNCING - an online resync onto the member is in progress: it receives
     *           client writes but serves no reads yet.
     */
    enum class MemberState { IN_SYNC, STALE, SYNCING };

    /*
     * One slot per configured member, in target-list order. Members that are
     * currently unusable keep their slot (reachable == false) so the
     * reconnect probe can bring them back.
     */
    struct Member {
        std::unique_ptr<rawstor::Connection> cn;
        rawstd::URI target;
        MemberState state;
        RawstorObjectMeta meta;
        bool reachable;
    };

    rawio::Queue& _queue;
    RawstdUUID _id;

    /* Configured mirror width N (the target list length). */
    size_t _nmirrors;
    std::vector<Member> _members;

    /* Logical object size, adopted from the in-sync metadata at open. */
    uint64_t _size;

    /* DIRTY has been durably recorded on the in-sync members. */
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

    /* Members marked STALE whose exclusion is not yet durably recorded. */
    size_t _unrecorded_stale;

    /* Current sync-set identity adopted at open / last barrier. */
    uint64_t _epoch;
    uint64_t _sync_id;
    uint64_t _sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];

    /*
     * Expires on destruction. Detached background work (read-repair,
     * resync, the reconnect probe, the degrade barriers they may trigger)
     * checks it before touching the object: unlike caller I/O, such work
     * is not covered by the "no I/O in flight at close" contract.
     */
    std::shared_ptr<int> _alive;

    /* Mirrored writes currently in flight (resync drain bookkeeping). */
    size_t _writes_in_flight;

    /* Active online resync, one member at a time. */
    std::unique_ptr<ResyncState> _resync;

    /*
     * Bumped every time a new ResyncState is created. Chunk-copy
     * completions capture the generation they were issued under: a
     * completion whose generation no longer matches _resync's (the
     * resync it belonged to was aborted and possibly replaced by a new
     * one) must not touch the current _resync, even though _resync
     * itself is non-null again.
     */
    size_t _resync_generation;

    /*
     * Periodic reconnect probe for unreachable members. The expirations
     * buffer is shared with the in-flight timer read: the object may be
     * destroyed before an asynchronous cancellation settles.
     */
    int _probe_fd;
    bool _probe_pending;
    std::shared_ptr<uint64_t> _probe_expirations;

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
        off_t offset, size_t size,
        std::function<void(Connection&, std::function<void(size_t, int)>&&)>&&
            issue,
        std::function<void(size_t, int)>&& cb
    );
    void _write_settled();

    void _resync_maybe_start();
    void _resync_sweep();
    void _resync_finish();
    void _resync_abort(const char* reason);

    void _probe_setup();
    void _probe_arm();
    void _probe_tick();

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
    ~Object();
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    std::vector<rawstd::URI> locations() const override;

    inline const RawstdUUID& id() const noexcept override { return _id; }

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void flush(std::function<void(size_t, int)>&& cb) override;

    /*
     * Clean close: flushes data and durably marks the in-sync members CLEAN,
     * then destroys the object. On any error the affected members are left
     * DIRTY (the safe direction) and the object is destroyed anyway; the
     * first error is reported.
     */
    void close(std::function<void(int)>&& cb) override;
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
