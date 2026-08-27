#ifndef RAWSTOR_VDUSE_VIRTQUEUE_HPP
#define RAWSTOR_VDUSE_VIRTQUEUE_HPP

#include <vduse/ring.hpp>

#include <rawstd/pipe.hpp>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <sys/uio.h>

#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <variant>
#include <vector>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace vduse {

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
 * Two layers live here, mirroring vhost::VirtQueue:
 *
 *  - The ring *mechanism* (set_vring_size/set_vring_base/set_vring_addr(
 *    AddressTranslator, ...)/pop/push/should_notify/last_avail_idx): plain,
 *    synchronous, no I/O, no Device dependency.
 *
 *  - Ownership and cross-thread *policy*: once attach()ed and start()ed,
 *    this VirtQueue owns its own OS thread, its own `rawio::Queue` (via the
 *    RawIOQueue* C ABI) and its own RawstorObject* (a fresh
 *    rawstor_target_open() against the same target every other VirtQueue
 *    uses) -- this is what lets N virtqueues make I/O progress in parallel
 *    on N cores instead of funneling through one shared reactor.
 *    `Device`'s control-plane thread never touches the mechanism layer
 *    directly on a *running* VirtQueue; every mutation crosses over via
 *    post_*()/get_vq_state()/pause()/resume(), landing on this VirtQueue's
 *    own thread. See virtqueue.cpp's top-of-file comment for the
 *    command-queue mechanics.
 *
 * Unlike vhost-user, VDUSE hands us no kick_fd of its own to forward --
 * we create it ourselves (eventfd(2)) on the control-plane thread (a
 * plain syscall, safe from any thread) and register it with the kernel
 * via VDUSE_VQ_SETUP_KICKFD there too, then post it over to this
 * VirtQueue's own thread the same way vhost::VirtQueue::apply(SetKickFd&&)
 * does. Likewise there is no per-virtqueue call_fd/err_fd: completions are
 * signalled via VDUSE_VQ_INJECT_IRQ, an ioctl on the shared device fd
 * (Device::inject_irq()) -- safe to call concurrently from every
 * VirtQueue's own thread, same as VDUSE_IOTLB_GET_FD (see
 * Device::iova_to_va()'s own doc comment).
 *
 * Everything that isn't purely local to this VirtQueue (IOVA translation,
 * negotiated features) lives on `Device` and is reached through the
 * `Device&` bound by attach() -- see Device's own class comment for how
 * that shared state is synchronized.
 */
class VirtQueue final {
public:
    /**
     * A reply slot a Reply-carrying command fulfils once applied; the
     * issuing (control-plane) thread blocks on the paired future. See
     * get_vq_state()/pause(), the only two callers.
     */
    template <typename T>
    struct Reply {
        std::promise<T> promise;
    };

private:
    struct SetVringSize {
        unsigned int size;
    };
    struct SetVringAddr {
        uint64_t desc_addr;
        uint64_t driver_addr;
        uint64_t device_addr;
    };
    struct SetKickFd {
        int fd;
    };
    struct SetEnabled {
        bool enabled;
    };
    struct Retranslate {};
    struct GetVqState {
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
        SetVringSize, SetVringAddr, SetKickFd, SetEnabled, Retranslate,
        GetVqState, Pause, Resume, FlushObject, Shutdown>;

    Ring _ring;

    /* Next head to pop from the avail ring. */
    uint16_t _last_avail_idx;

    /* Next index we will publish into the used ring. */
    uint16_t _used_idx;

    int _kick_fd;
    bool _enabled;
    bool _kick_armed;

    /*
     * Whether should_notify()'s EVENT_IDX arithmetic can be trusted
     * against the driver's actual used_event right now -- see
     * vhost::VirtQueue::_signalled_used_valid for the full rationale (same
     * idea: false right after the ring addresses are (re)set, so the
     * first completion always notifies unconditionally).
     */
    bool _signalled_used_valid;

    /* Set by attach(), before start(): which Device/index we belong to. */
    Device* _device;
    size_t _index;

    /* Owned for this VirtQueue's whole running lifetime, created in run()
     * (on the worker thread itself) and torn down there too -- never
     * touched from any other thread once start() returns. */
    RawIOQueue* _queue;
    RawstorObject* _object;
    std::thread _thread;

    /* Cross-thread command inbox; see virtqueue.cpp. Empty until start()
     * creates it (never before, never again after); the whole point of a
     * separate rawstd::Pipe from _kick_fd is that it needs no -1 sentinel
     * of its own to track "not yet created". */
    std::mutex _cmd_mutex;
    std::deque<Command> _cmds;
    std::optional<rawstd::Pipe> _wake_pipe;

    /* Worker-thread-only state (never touched from the control-plane
     * thread): whether kick-driven descriptor popping is currently
     * suppressed (see pause()/resume()), how many Request objects are
     * currently in flight, and replies to Pause commands waiting for that
     * count to reach zero. */
    bool _paused;
    unsigned int _inflight;
    std::vector<Reply<void>> _pending_pauses;
    bool _stop_requested;

    void set_kick_fd(int fd);
    void set_enabled(bool enabled);

    void apply(SetVringSize&& cmd);
    void apply(SetVringAddr&& cmd);
    void apply(SetKickFd&& cmd);
    void apply(SetEnabled&& cmd);
    void apply(Retranslate&& cmd);
    void apply(GetVqState&& cmd);
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
        _enabled(false),
        _kick_armed(false),
        _signalled_used_valid(false),
        _device(nullptr),
        _index(0),
        _queue(nullptr),
        _object(nullptr),
        _paused(false),
        _inflight(0),
        _stop_requested(false) {}
    VirtQueue(const VirtQueue&) = delete;
    VirtQueue(VirtQueue&&) = delete;
    ~VirtQueue();

    VirtQueue& operator=(const VirtQueue&) = delete;
    VirtQueue& operator=(VirtQueue&&) = delete;

    // --- ring mechanism: plain, synchronous, no I/O. ---

    inline uint16_t last_avail_idx() const noexcept { return _last_avail_idx; }

    void set_vring_size(unsigned int size) { _ring.set_num(size); }

    void set_vring_base(uint16_t idx) noexcept { _last_avail_idx = idx; }

    void set_vring_addr(
        const AddressTranslator& translate, uint64_t desc_addr,
        uint64_t driver_addr, uint64_t device_addr
    );

    /** Forget the ring, e.g. when the virtqueue is disabled/torn down. */
    void clear_vring_addr() noexcept { _ring.clear(); }

    /**
     * Pop the next available descriptor chain, translating IOVAs
     * (including a single level of indirection) into host virtual
     * addresses via `translate`. Returns nullptr if nothing is available.
     */
    std::unique_ptr<DescChain> pop(const AddressTranslator& translate);

    /**
     * Publish a completion for the descriptor chain starting at `head`
     * with `len` bytes written into the writable buffers.
     */
    void push(uint16_t head, uint32_t len);

    /**
     * Whether the driver currently needs to be signalled (via
     * VDUSE_VQ_INJECT_IRQ), given VIRTIO_RING_F_EVENT_IDX negotiation
     * state. No I/O, but not purely const: it advances the "have we
     * signalled at least once since the ring was (re)mapped" bookkeeping.
     * Must be evaluated once per push(), immediately after it.
     */
    bool should_notify(bool event_idx_negotiated) noexcept;

    // --- ownership and lifecycle ---

    /**
     * Bind this VirtQueue to its owning Device and virtqueue index. Must
     * be called before start(), from the control-plane thread, before any
     * other thread can see this VirtQueue.
     */
    void attach(Device& device, size_t index) noexcept {
        _device = &device;
        _index = index;
    }

    /**
     * Create this VirtQueue's own RawIOQueue and RawstorObject (a fresh
     * rawstor_target_open() against `target`) and start its worker
     * thread. Blocks until both are ready, or rethrows whatever exception
     * the worker thread hit trying to create them -- in which case the
     * worker thread has already exited and this VirtQueue is back to its
     * not-started state (running() is false).
     */
    void start(const std::string& target, unsigned int queue_size);

    inline bool running() const noexcept { return _thread.joinable(); }

    /**
     * Post a Shutdown command and join the worker thread. A no-op if
     * this VirtQueue was never start()ed. Only ~Device() calls this.
     */
    void stop() noexcept;

    // --- cross-thread policy: callable only once this VirtQueue is
    // running(), and only from the control-plane thread (except
    // post_flush(), see its own doc comment). ---

    void post_set_vring_size(unsigned int size);
    void post_set_vring_addr(
        uint64_t desc_addr, uint64_t driver_addr, uint64_t device_addr
    );

    /**
     * Assign a freshly created, kernel-registered kick_fd (created and
     * VDUSE_VQ_SETUP_KICKFD-registered by the caller, on the
     * control-plane thread) to this VirtQueue. Ownership of `fd` passes
     * to this VirtQueue; it is closed on the next post_set_kick_fd() or
     * when disabling (see post_set_enabled()).
     */
    void post_set_kick_fd(int fd);

    /**
     * Enable or disable this virtqueue. Disabling cancels the pending
     * kick_fd read, closes kick_fd, and clears the ring mapping -- vduse
     * always tears both fully down on disable and rebuilds them fresh on
     * the next enable, unlike vhost-user's persistent-across-toggles
     * kick_fd. A no-op if already in the requested state.
     */
    void post_set_enabled(bool enabled);

    /**
     * Re-resolve this virtqueue's ring to host virtual addresses using
     * the IOVAs last passed to post_set_vring_addr(), via
     * device.iova_to_va() -- used after a VDUSE_UPDATE_IOTLB control
     * message invalidates cached translations. A no-op if the ring isn't
     * currently mapped (disabled/never enabled).
     */
    void post_retranslate();

    /**
     * Return this virtqueue's current avail-ring consumption point,
     * matching VDUSE_GET_VQ_STATE semantics. Blocks the calling
     * (control-plane) thread until the worker thread has replied.
     */
    uint16_t get_vq_state();

    /**
     * Stop popping new descriptors and block the calling (control-plane)
     * thread until every already in-flight request on this VirtQueue has
     * completed. Must be paired with a later resume() -- used by
     * Device::remove_iova_regions() callers to make it safe to munmap()
     * an IOVA region no in-flight request can still be translating
     * addresses into.
     */
    void pause();

    /**
     * Resume descriptor popping after pause(), and immediately process
     * whatever accumulated on the ring while paused (no new kick is
     * guaranteed to arrive to trigger that on its own).
     */
    void resume();

    /**
     * Flush this VirtQueue's own backing object and return a future that
     * becomes ready once that completes (or holds the exception should
     * it fail) -- see Device::post_flush_others(), the only caller: a
     * VIRTIO_BLK_T_FLUSH request handled on one VirtQueue must make
     * durable every write issued through *any* VirtQueue, since each has
     * its own independent RawstorObject (see the class comment). Unlike
     * everything else in this section, safe to call from another
     * VirtQueue's own worker thread too -- just never from this same
     * VirtQueue's own thread. Posting is non-blocking; only the returned
     * future's get()/wait() blocks.
     */
    std::future<void> post_flush();

    // --- worker-thread-only: public only because they're called from
    // free-function completion callbacks in virtqueue.cpp (kick_cb/
    // wake_cb), which can't reach private members -- calling any of
    // these from anywhere but this VirtQueue's own thread is undefined.
    // ---

    /**
     * Arm (or re-arm) the asynchronous read that waits for the next kick
     * on this virtqueue's own kick_fd, via this VirtQueue's own queue. A
     * no-op if already armed, kick processing is disabled, or no kick_fd
     * is set.
     */
    void arm_kick();

    void clear_kick_armed() noexcept { _kick_armed = false; }

    /* Arms the wake-fd read that lets post() interrupt this VirtQueue's
     * own rawio_wait() from another thread; see virtqueue.cpp. */
    void arm_wake();

    void drain_commands();

    /**
     * Convenience overload translating IOVAs via device.iova_to_va()
     * and, if device.event_idx_negotiated(), publishing avail_event so
     * the driver knows not to kick again until last_avail_idx moves past
     * this point (mirrors vhost::VirtQueue::pop(const Device&)).
     */
    std::unique_ptr<DescChain> pop(Device& device);

    /** This VirtQueue's own backing object -- see the class comment. */
    inline RawstorObject* object() const noexcept { return _object; }

    /** The Device this VirtQueue was attach()ed to. */
    inline Device& device() const noexcept { return *_device; }

    /**
     * Signal the driver (VDUSE_VQ_INJECT_IRQ on `device`'s fd) if
     * should_notify() holds. Must be called once per push(), immediately
     * after it.
     */
    void notify(Device& device, bool event_idx_negotiated);

    /**
     * Drain and process every descriptor chain currently available,
     * dispatching each as a virtio-blk request against this VirtQueue's
     * own backing rawstor object. Called from the kick_fd handler; may
     * leave I/O in flight (it never blocks). A no-op while paused (see
     * pause()/resume()).
     */
    void process_queue();

    /**
     * Publish a completion (used-ring push + notify) for the descriptor
     * chain identified by `head`, and account for one fewer in-flight
     * request (see pause()).
     */
    void complete_request(uint16_t head, uint32_t len);
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_VIRTQUEUE_HPP
