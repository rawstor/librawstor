#ifndef RAWSTOR_VHOST_VIRTQUEUE_HPP
#define RAWSTOR_VHOST_VIRTQUEUE_HPP

#include <vhost/ring.hpp>
#include <vhost/user_protocol.h>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <sys/uio.h>

#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vhost {

class Device;

/**
 * A single descriptor chain popped from the avail ring, split into the
 * driver-readable (out) and driver-writable (in) buffers, already
 * translated into host virtual addresses.
 */
struct DescChain {
    uint16_t head;
    std::vector<iovec> readable;
    std::vector<iovec> writable;
};

/**
 * One virtqueue.
 *
 * Two layers live here:
 *
 *  - The ring *mechanism* (set_vring_size/set_vring_base/set_vring_addr(
 *    AddressTranslator, ...)/pop/push/should_notify/last_avail_idx):
 *    plain, synchronous, no I/O, no Device dependency -- unit-tested in
 *    isolation against a bare VirtQueue in vhost/tests/test_virtqueue.cpp
 *    exactly as before this class owned a thread. Safe to call directly
 *    as long as nothing else is concurrently touching the same instance.
 *
 *  - Ownership and cross-thread *policy*: once attach()ed and start()ed,
 *    this VirtQueue owns its own OS thread, its own `rawio::Queue` (via
 *    the RawIOQueue* C ABI) and its own RawstorObject* (a fresh
 *    rawstor_target_open() against the same target every other VirtQueue
 *    and Device::spec() use) -- this is what lets N virtqueues make I/O
 *    progress in parallel on N cores instead of funneling through one
 *    shared reactor. `Device`'s control-plane thread never touches the
 *    mechanism layer directly on a *running* VirtQueue; every mutation
 *    crosses over via post_*()/get_vring_base()/pause()/resume(), landing
 *    on this VirtQueue's own thread. See virtqueue.cpp's top-of-file
 *    comment for the command-queue mechanics.
 *
 * Everything that isn't purely local to this VirtQueue (guest memory
 * region translation, negotiated features/config) lives on `Device` and
 * is reached through the `Device&` bound by attach() -- see Device's own
 * class comment for how that shared state is synchronized.
 */
class VirtQueue final {
public:
    /**
     * A reply slot a Reply-carrying command fulfils once applied; the
     * issuing (control-plane) thread blocks on the paired future. See
     * get_vring_base()/pause(), the only two callers.
     */
    template <typename T>
    struct Reply {
        std::promise<T> promise;
    };

private:
    struct SetVringSize {
        unsigned int size;
    };
    struct SetVringBase {
        uint16_t idx;
    };
    struct SetKickFd {
        int fd;
    };
    struct SetCallFd {
        int fd;
    };
    struct SetErrFd {
        int fd;
    };
    struct SetVringAddr {
        vhost_vring_addr vra;
    };
    struct SetEnabled {
        bool enabled;
    };
    struct GetVringBase {
        Reply<uint16_t> reply;
    };
    struct Pause {
        Reply<void> reply;
    };
    struct Resume {};
    struct FlushObject {
        Reply<void> reply;
    };
    struct Shutdown {};

    using Command = std::variant<
        SetVringSize, SetVringBase, SetKickFd, SetCallFd, SetErrFd,
        SetVringAddr, SetEnabled, GetVringBase, Pause, Resume, FlushObject,
        Shutdown>;

    Ring _ring;

    /* Next head to pop from the avail ring. */
    uint16_t _last_avail_idx;

    /* Next index we will publish into the used ring. */
    uint16_t _used_idx;

    int _kick_fd;
    int _call_fd;
    int _err_fd;
    /*
     * Reference count of independent reasons this virtqueue should be
     * considered enabled (protocol SET_VRING_ENABLE plus any other
     * caller, e.g. GET_VRING_BASE's forced stop). kick_fd only actually
     * gets armed/disarmed on the 0<->1 transition, mirroring
     * rawstor-vhost-qemu's Watcher ref-count around set_watch/
     * remove_watch: overlapping enable/disable calls must not tear down
     * (or redundantly re-arm) state that another caller still needs.
     */
    int _enable_count;
    bool _kick_armed;

    /*
     * Whether should_notify()'s EVENT_IDX arithmetic can be trusted
     * against the driver's actual used_event right now. It cannot right
     * after a (re)connect: the ring may have moved to fresh guest
     * memory whose used_event the driver hasn't necessarily set to a
     * value consistent with our freshly-reset _used_idx yet, and
     * should_notify()'s "old = new - 1" bookkeeping only holds once we
     * have actually delivered at least one notification since. Until
     * then, notify unconditionally -- mirrors libvhost-user's
     * signalled_used_valid, which starts false for the same reason.
     */
    bool _signalled_used_valid;

    /* Set by attach(), before start(): which Device/index we belong to. */
    Device* _device;
    size_t _index;

    /* Owned for this VirtQueue's whole running lifetime, created in
     * run() (on the worker thread itself) and torn down there too --
     * never touched from any other thread once start() returns. */
    RawIOQueue* _queue;
    RawstorObject* _object;
    std::thread _thread;

    /* Cross-thread command inbox; see virtqueue.cpp. */
    std::mutex _cmd_mutex;
    std::deque<Command> _cmds;
    int _wake_read_fd;
    int _wake_write_fd;

    /* Worker-thread-only state (never touched from the control-plane
     * thread): whether kick-driven descriptor popping is currently
     * suppressed (see pause()/resume()), how many Request objects are
     * currently in flight, and replies to Pause commands waiting for
     * that count to reach zero. */
    bool _paused;
    unsigned int _inflight;
    std::vector<Reply<void>> _pending_pauses;
    bool _stop_requested;

    /**
     * Prime call_fd with an immediate wakeup, working around the
     * front-end's interrupt route for it (e.g. a KVM irqfd) not
     * necessarily being wired up yet at the instant we start relying
     * on it -- see the .cpp for the full rationale. A no-op if there
     * is no call_fd.
     */
    void prime_call_fd() noexcept;

    void set_kick_fd(int fd);
    void set_call_fd(int fd);
    void set_err_fd(int fd);
    void set_enabled(bool enabled);

    void apply(SetVringSize&& cmd);
    void apply(SetVringBase&& cmd);
    void apply(SetKickFd&& cmd);
    void apply(SetCallFd&& cmd);
    void apply(SetErrFd&& cmd);
    void apply(SetVringAddr&& cmd);
    void apply(SetEnabled&& cmd);
    void apply(GetVringBase&& cmd);
    void apply(Pause&& cmd);
    void apply(Resume&& cmd);
    // Defined in virtqueue_worker.cpp, not virtqueue.cpp: needs
    // co_object_flush(), which lives there alongside the rest of the
    // data-plane's rawstor_object_*() bridging.
    void apply(FlushObject&& cmd);
    void apply(Shutdown&& cmd);

    void post(Command cmd);

    /* The worker thread's entry point: creates _queue/_object, runs the
     * reactor loop until a Shutdown command lands, then tears both back
     * down. `ready` is fulfilled (or given the startup exception) once
     * _queue/_object are usable, before the reactor loop is entered. */
    void
    run(std::string target, unsigned int queue_size, std::promise<void> ready);

public:
    VirtQueue() :
        _last_avail_idx(0),
        _used_idx(0),
        _kick_fd(-1),
        _call_fd(-1),
        _err_fd(-1),
        _enable_count(0),
        _kick_armed(false),
        _signalled_used_valid(false),
        _device(nullptr),
        _index(0),
        _queue(nullptr),
        _object(nullptr),
        _wake_read_fd(-1),
        _wake_write_fd(-1),
        _paused(false),
        _inflight(0),
        _stop_requested(false) {}
    VirtQueue(const VirtQueue&) = delete;
    VirtQueue(VirtQueue&&) = delete;
    ~VirtQueue();

    VirtQueue& operator=(const VirtQueue&) = delete;
    VirtQueue& operator=(VirtQueue&&) = delete;

    // --- ring mechanism: plain, synchronous, no I/O; unit-tested
    // directly against a bare (unattached) VirtQueue. ---

    inline uint16_t last_avail_idx() const noexcept { return _last_avail_idx; }

    void set_vring_size(unsigned int size) { _ring.set_num(size); }

    void set_vring_base(uint16_t idx) noexcept { _last_avail_idx = idx; }

    void set_vring_addr(
        const AddressTranslator& translate, const vhost_vring_addr& vra
    );

    /**
     * Pop the next available descriptor chain, translating guest
     * addresses (including a single level of indirection) into host
     * virtual addresses via `translate`. Returns nullptr if nothing is
     * available.
     */
    std::unique_ptr<DescChain> pop(const AddressTranslator& translate);

    /**
     * Publish a completion for the descriptor chain starting at `head`
     * with `len` bytes written into the writable buffers.
     */
    void push(uint16_t head, uint32_t len);

    /**
     * Whether the driver currently needs to be signalled (via call_fd),
     * given VIRTIO_RING_F_EVENT_IDX negotiation state. No I/O, but not
     * purely const: it advances the "have we signalled at least once
     * since (re)connecting" bookkeeping used to force the first check
     * to notify unconditionally. Must be evaluated once per push(),
     * immediately after it.
     */
    bool should_notify(bool event_idx_negotiated) noexcept;

    // --- ownership and lifecycle ---

    /**
     * Bind this VirtQueue to its owning Device and virtqueue index.
     * Must be called before start(), from the control-plane thread,
     * before any other thread can see this VirtQueue.
     */
    void attach(Device& device, size_t index) noexcept {
        _device = &device;
        _index = index;
    }

    /**
     * Create this VirtQueue's own RawIOQueue and RawstorObject (a fresh
     * rawstor_target_open() against `target`) and start its worker
     * thread. Blocks until both are ready, or rethrows whatever
     * exception the worker thread hit trying to create them -- in
     * which case the worker thread has already exited and this
     * VirtQueue is back to its not-started state (running() is false).
     */
    void start(const std::string& target, unsigned int queue_size);

    inline bool running() const noexcept { return _thread.joinable(); }

    /**
     * Post a Shutdown command and join the worker thread. A no-op if
     * this VirtQueue was never start()ed. Only ~Device() calls this.
     */
    void stop() noexcept;

    // --- cross-thread policy: callable only once this VirtQueue is
    // running(), and (except for post_flush(), see its own doc comment)
    // only from the control-plane thread. ---

    void post_set_vring_size(unsigned int size);
    void post_set_vring_base(uint16_t idx);
    void post_set_kick_fd(int fd);
    void post_set_call_fd(int fd);
    void post_set_err_fd(int fd);
    void post_set_vring_addr(const vhost_vring_addr& vra);
    void post_set_enabled(bool enabled);

    /**
     * Disable this virtqueue and return the index up to which it has
     * consumed the avail ring, matching vhost-user's GET_VRING_BASE
     * semantics. Blocks the calling (control-plane) thread until the
     * worker thread has applied it. Does not wait for already
     * in-flight requests to complete -- same as before this VirtQueue
     * owned its own thread, that index is a ring-position bookkeeping
     * value, not an I/O completion barrier.
     */
    uint16_t get_vring_base();

    /**
     * Stop popping new descriptors and block the calling
     * (control-plane) thread until every already in-flight request on
     * this VirtQueue has completed. Must be paired with a later
     * resume() -- used by Device::rem_mem_reg() to make it safe to
     * munmap() a guest memory region no in-flight request can still be
     * translating addresses into.
     */
    void pause();

    /**
     * Resume descriptor popping after pause(), and immediately process
     * whatever accumulated on the ring while paused (no new kick is
     * guaranteed to arrive to trigger that on its own).
     */
    void resume();

    /**
     * Flush this VirtQueue's own backing object and return a future
     * that becomes ready once that completes (or holds the exception
     * should it fail) -- see Device::post_flush_others(), the only
     * caller: a VIRTIO_BLK_T_FLUSH request handled on one VirtQueue must
     * make durable every write issued through *any* VirtQueue, since
     * each has its own independent RawstorObject (see the class
     * comment). Unlike everything else in this section, safe to call
     * from another VirtQueue's own worker thread too -- just never from
     * this same VirtQueue's own thread (it would be posting a command to
     * itself and then blocking the very thread that would apply it).
     * Posting is non-blocking; only the returned future's get()/wait()
     * blocks.
     */
    std::future<void> post_flush();

    // --- worker-thread-only: public only because they're called from
    // free-function completion callbacks in virtqueue.cpp (kick_cb/
    // wake_cb), which can't reach private members -- not part of the
    // cross-thread-safe surface above; calling any of these from
    // anywhere but this VirtQueue's own thread is undefined. ---

    /**
     * Arm (or re-arm) the asynchronous read that waits for the next
     * kick on this virtqueue's own kick_fd, via this VirtQueue's own
     * queue. A no-op if already armed, kick processing is disabled, or
     * no kick_fd is set.
     */
    void arm_kick();

    void clear_kick_armed() noexcept { _kick_armed = false; }

    /* Arms the wake-fd read that lets post() interrupt this VirtQueue's
     * own rawio_wait() from another thread; see virtqueue.cpp. */
    void arm_wake();

    void drain_commands();

    /**
     * Convenience overload translating addresses (guest physical
     * addresses, as written by the guest driver into the descriptors)
     * via device.guest_phys_to_va().
     */
    std::unique_ptr<DescChain> pop(const Device& device);

    /** This VirtQueue's own backing object -- see the class comment. */
    inline RawstorObject* object() const noexcept { return _object; }

    /** The Device this VirtQueue was attach()ed to. */
    inline Device& device() const noexcept { return *_device; }

    /**
     * Signal the driver (write to call_fd, via this VirtQueue's own
     * queue) if should_notify() holds. Must be called once per push(),
     * immediately after it.
     */
    void notify(bool event_idx_negotiated);

    /**
     * Drain and process every descriptor chain currently available,
     * dispatching each as a virtio-blk request against this VirtQueue's
     * own backing rawstor object. Called from the kick_fd handler; may
     * leave I/O in flight (it never blocks). A no-op while paused (see
     * pause()/resume()).
     */
    void process_queue();

    /**
     * Publish a completion (used-ring push + notify) for the
     * descriptor chain identified by `head`, and account for one fewer
     * in-flight request (see pause()).
     */
    void complete_request(uint16_t head, uint32_t len);
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_VIRTQUEUE_HPP
