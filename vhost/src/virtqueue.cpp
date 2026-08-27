#include <vhost/virtqueue.hpp>

#include "device.hpp"
#include <stdheaders/linux/virtio_ring.h>

#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <rawstor/rawio.h>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

// ---------------------------------------------------------------------
// This file owns two things: the ring mechanism (unchanged from before
// VirtQueue owned a thread -- set_vring_size/set_vring_base/
// set_vring_addr(AddressTranslator, ...)/pop/push/should_notify, still
// plain and synchronous, still unit-tested directly against a bare
// VirtQueue in vhost/tests/test_virtqueue.cpp), and the cross-thread
// *policy* that lets Device's control-plane thread safely reach a
// VirtQueue that owns and is driven by its own OS thread:
//
//   - post_*()/get_vring_base()/pause()/resume(), called only from the
//     control-plane thread on a running() VirtQueue, enqueue a Command
//     into `_cmds` (guarded by `_cmd_mutex`) and wake the owning
//     thread's reactor via a self-pipe (`_wake_read_fd`/`_wake_write_fd`
//     -- a plain pipe rather than eventfd(), matching CLAUDE.md's
//     portability guidance outside librawio's io_uring backend).
//     get_vring_base()/pause() additionally block on a std::promise/
//     future pair (Reply<T>) until the owning thread has actually
//     applied the command -- acceptable only because both are rare,
//     off-the-hot-path control-plane operations (see their own doc
//     comments in virtqueue.hpp).
//   - The owning thread's reactor (run(), in virtqueue_worker.cpp) keeps
//     a read armed on `_wake_read_fd` via this same VirtQueue's own
//     `_queue`, mirroring kick_fd's arm_kick()/kick_cb rearm pattern
//     below. Each wakeup drains and applies every queued Command in
//     order (drain_commands()/apply()), then rearms.
//
// Every apply() overload runs exclusively on the owning thread, so it's
// free to touch `_kick_fd`/`_queue` et al. directly with no locking of
// its own -- the whole point of routing through the command queue is
// that nothing else ever does.
// ---------------------------------------------------------------------

namespace {

using rawstor::vhost::Device;
using rawstor::vhost::VirtQueue;

void close_fd(int fd, const char* what) {
    rawstd_info("fd %d: Close (%s)\n", fd, what);
    if (close(fd) == -1) {
        int error = errno;
        errno = 0;
        rawstd_error(
            "VirtQueue: close(%s) failed: %s\n", what, strerror(error)
        );
    }
}

struct KickCtx {
    VirtQueue* vq;
    uint64_t value;
};

int kick_cb(ssize_t result, void* data) {
    std::unique_ptr<KickCtx> ctx(static_cast<KickCtx*>(data));

    // The armed read this callback belongs to has now completed one way
    // or another; clear it up front so a re-arm below (or a later call
    // to arm_kick()) is not mistaken for one already in flight.
    ctx->vq->clear_kick_armed();

    if (result == -ECANCELED) {
        return 0;
    }

    if (result < 0) {
        rawstd_error("vhost: kick_fd read failed: %s\n", strerror(-result));
        return 0;
    }

    if (static_cast<size_t>(result) != sizeof(ctx->value)) {
        rawstd_error("vhost: unexpected kick_fd read size: %zd\n", result);
        return 0;
    }

    VirtQueue* vq = ctx->vq;

    try {
        vq->process_queue();
    } catch (const std::exception& e) {
        rawstd_error("vhost: error processing virtqueue: %s\n", e.what());
    }

    try {
        vq->arm_kick();
    } catch (const std::exception& e) {
        rawstd_error("vhost: failed to rearm kick_fd: %s\n", e.what());
    }

    return 0;
}

struct NotifyCtx {
    uint64_t value;
};

int notify_cb(ssize_t result, void* data) {
    std::unique_ptr<NotifyCtx> ctx(static_cast<NotifyCtx*>(data));

    if (result < 0 && result != -ECANCELED) {
        rawstd_error("vhost: call_fd write failed: %s\n", strerror(-result));
        return 0;
    }

    if (result >= 0 && static_cast<size_t>(result) != sizeof(ctx->value)) {
        rawstd_error("vhost: unexpected call_fd write size: %zd\n", result);
        return 0;
    }

    rawstd_debug("vhost: notify: call_fd write completed\n");

    return 0;
}

struct WakeCtx {
    VirtQueue* vq;
    char byte;
};

int wake_cb(ssize_t result, void* data) {
    std::unique_ptr<WakeCtx> ctx(static_cast<WakeCtx*>(data));

    if (result == -ECANCELED) {
        return 0;
    }

    if (result < 0) {
        rawstd_error("vhost: wake_fd read failed: %s\n", strerror(-result));
        return 0;
    }

    VirtQueue* vq = ctx->vq;

    vq->drain_commands();

    try {
        vq->arm_wake();
    } catch (const std::exception& e) {
        rawstd_error("vhost: failed to rearm wake_fd: %s\n", e.what());
    }

    return 0;
}

} // namespace

namespace rawstor {
namespace vhost {

void VirtQueue::prime_call_fd() noexcept {
    if (_call_fd == -1) {
        return;
    }

    /*
     * The front-end's interrupt route for call_fd (e.g. a KVM irqfd) is
     * not necessarily wired up the instant it hands us the fd or
     * (re-)enables the queue -- notably across a reconnect/
     * renegotiation, where SET_VRING_ENABLE toggles off and back on
     * around a new SET_VRING_ADDR without necessarily replacing
     * call_fd itself. A notify() landing in that gap increments the
     * eventfd's counter without ever triggering an interrupt, and
     * nothing re-checks a stale non-zero counter once the route is
     * finally established, so the driver would wait for that
     * completion forever. Priming here mirrors libvhost-user's
     * vu_set_vring_call_exec(), which does the same "in case of I/O
     * hang after reconnecting" -- except we also do it on every enable,
     * since re-enabling appears to re-establish the route just as a
     * fresh SET_VRING_CALL does.
     */
    uint64_t one = 1;
    if (write(_call_fd, &one, sizeof(one)) != sizeof(one)) {
        rawstd_error(
            "vhost: failed to prime call_fd %d: %s\n", _call_fd, strerror(errno)
        );
    }
}

VirtQueue::~VirtQueue() {
    if (running()) {
        stop();
    }

    if (_kick_fd != -1) {
        close_fd(_kick_fd, "kick_fd");
    }
    if (_call_fd != -1) {
        close_fd(_call_fd, "call_fd");
    }
    if (_err_fd != -1) {
        close_fd(_err_fd, "err_fd");
    }
    if (_wake_read_fd != -1) {
        close_fd(_wake_read_fd, "wake_read_fd");
    }
    if (_wake_write_fd != -1) {
        close_fd(_wake_write_fd, "wake_write_fd");
    }
}

void VirtQueue::start(const std::string& target, unsigned int queue_size) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        RAWSTD_THROW_ERRNO();
    }
    _wake_read_fd = pipefd[0];
    _wake_write_fd = pipefd[1];

    int nonblock_res = rawstd_socket_set_nonblock(_wake_read_fd);
    if (!nonblock_res) {
        nonblock_res = rawstd_socket_set_nonblock(_wake_write_fd);
    }
    if (nonblock_res) {
        RAWSTD_THROW_SYSTEM_ERROR(-nonblock_res);
    }

    std::promise<void> ready;
    std::future<void> ready_future = ready.get_future();

    // SIGINT/SIGTERM are process-wide: the kernel delivers them to some
    // arbitrary thread that doesn't have them blocked, which could just
    // as well be this new worker thread as the control-plane thread
    // that actually knows how to act on them (Device::loop()'s EINTR
    // handling). A signal landing on a worker thread would just make
    // that one rawio_wait() return EINTR -- harmlessly retried, see
    // run() -- while the rest of the process never learns the signal
    // arrived at all, so shutdown would hang instead of happening. Block
    // every signal on this (control-plane) thread before spawning, so
    // the child inherits an all-blocked mask, then restore this
    // thread's own mask right after -- standard "spawn workers with
    // signals blocked" idiom.
    sigset_t all_signals, old_mask;
    sigfillset(&all_signals);
    pthread_sigmask(SIG_BLOCK, &all_signals, &old_mask);

    _thread = std::thread(
        &VirtQueue::run, this, target, queue_size, std::move(ready)
    );

    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);

    // Propagates whatever exception run() hit trying to create
    // _queue/_object -- in which case run() has already returned (the
    // thread function exits without entering its reactor loop), so
    // join() right after rethrowing below leaves this VirtQueue back in
    // its not-started state (running() false) rather than leaking a
    // detached thread.
    try {
        ready_future.get();
    } catch (...) {
        _thread.join();
        throw;
    }
}

void VirtQueue::stop() noexcept {
    if (!running()) {
        return;
    }
    post(Shutdown{});
    _thread.join();
}

void VirtQueue::post(Command cmd) {
    {
        std::lock_guard<std::mutex> lock(_cmd_mutex);
        _cmds.push_back(std::move(cmd));
    }
    char b = 1;
    // Best effort: the pipe is non-blocking and its buffer is many
    // orders of magnitude larger than the command traffic this ever
    // sees, so EAGAIN here just means a wakeup byte from an earlier
    // post() is already pending -- the command we just enqueued will
    // still be drained by the wakeup that byte causes, so it's not an
    // error, merely redundant.
    ssize_t res = write(_wake_write_fd, &b, 1);
    if (res == -1 && errno != EAGAIN) {
        rawstd_error(
            "vhost: failed to wake virtqueue worker: %s\n", strerror(errno)
        );
    }
    errno = 0;
}

void VirtQueue::post_set_vring_size(unsigned int size) {
    post(SetVringSize{size});
}

void VirtQueue::post_set_vring_base(uint16_t idx) {
    post(SetVringBase{idx});
}

void VirtQueue::post_set_kick_fd(int fd) {
    post(SetKickFd{fd});
}

void VirtQueue::post_set_call_fd(int fd) {
    post(SetCallFd{fd});
}

void VirtQueue::post_set_err_fd(int fd) {
    post(SetErrFd{fd});
}

void VirtQueue::post_set_vring_addr(const vhost_vring_addr& vra) {
    post(SetVringAddr{vra});
}

void VirtQueue::post_set_enabled(bool enabled) {
    post(SetEnabled{enabled});
}

uint16_t VirtQueue::get_vring_base() {
    GetVringBase cmd;
    std::future<uint16_t> f = cmd.reply.promise.get_future();
    post(std::move(cmd));
    return f.get();
}

void VirtQueue::pause() {
    Pause cmd;
    std::future<void> f = cmd.reply.promise.get_future();
    post(std::move(cmd));
    f.get();
}

void VirtQueue::resume() {
    post(Resume{});
}

std::future<void> VirtQueue::post_flush() {
    FlushObject cmd;
    std::future<void> f = cmd.reply.promise.get_future();
    post(std::move(cmd));
    return f;
}

void VirtQueue::drain_commands() {
    std::deque<Command> local;
    {
        std::lock_guard<std::mutex> lock(_cmd_mutex);
        local.swap(_cmds);
    }
    for (Command& cmd : local) {
        std::visit([this](auto&& c) { apply(std::move(c)); }, std::move(cmd));
    }
}

void VirtQueue::apply(SetVringSize&& cmd) {
    set_vring_size(cmd.size);
}

void VirtQueue::apply(SetVringBase&& cmd) {
    set_vring_base(cmd.idx);
}

void VirtQueue::apply(SetKickFd&& cmd) {
    set_kick_fd(cmd.fd);
}

void VirtQueue::apply(SetCallFd&& cmd) {
    set_call_fd(cmd.fd);
}

void VirtQueue::apply(SetErrFd&& cmd) {
    set_err_fd(cmd.fd);
}

void VirtQueue::apply(SetVringAddr&& cmd) {
    Device& device = *_device;
    set_vring_addr(
        [&device](uint64_t addr) { return device.userspace_va_to_va(addr); },
        cmd.vra
    );
}

void VirtQueue::apply(SetEnabled&& cmd) {
    set_enabled(cmd.enabled);
}

void VirtQueue::apply(GetVringBase&& cmd) {
    set_enabled(false);
    cmd.reply.promise.set_value(_last_avail_idx);
}

void VirtQueue::apply(Pause&& cmd) {
    _paused = true;
    if (_inflight == 0) {
        cmd.reply.promise.set_value();
    } else {
        _pending_pauses.push_back(std::move(cmd.reply));
    }
}

void VirtQueue::apply(Resume&& /*cmd*/) {
    _paused = false;
    try {
        process_queue();
    } catch (const std::exception& e) {
        rawstd_error("vhost: error processing virtqueue: %s\n", e.what());
    }
}

void VirtQueue::apply(Shutdown&& /*cmd*/) {
    _stop_requested = true;
}

void VirtQueue::arm_kick() {
    rawstd_debug(
        "vhost: arm_kick(vq=%zu): kick_armed=%d kick_fd=%d\n", _index,
        _kick_armed, _kick_fd
    );

    if (_kick_armed || _kick_fd == -1) {
        return;
    }

    std::unique_ptr<KickCtx> ctx = std::make_unique<KickCtx>();
    ctx->vq = this;
    ctx->value = 0;

    int res = rawio_read(
        _queue, _kick_fd, &ctx->value, sizeof(ctx->value), kick_cb, ctx.get()
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    _kick_armed = true;
    ctx.release();
}

void VirtQueue::arm_wake() {
    std::unique_ptr<WakeCtx> ctx = std::make_unique<WakeCtx>();
    ctx->vq = this;
    ctx->byte = 0;

    int res =
        rawio_read(_queue, _wake_read_fd, &ctx->byte, 1, wake_cb, ctx.get());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    ctx.release();
}

void VirtQueue::set_kick_fd(int fd) {
    if (_kick_fd != -1) {
        int res = rawio_cancel_all(_queue, _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vhost: failed to cancel pending kick_fd ops: %s\n",
                strerror(-res)
            );
        }
        close_fd(_kick_fd, "kick_fd");
    }

    _kick_fd = fd;
    _kick_armed = false;

    if (_enable_count > 0 && _kick_fd != -1) {
        arm_kick();
    }
}

void VirtQueue::set_call_fd(int fd) {
    if (_call_fd != -1) {
        close_fd(_call_fd, "call_fd");
    }
    _call_fd = fd;
    prime_call_fd();
}

void VirtQueue::set_err_fd(int fd) {
    if (_err_fd != -1) {
        close_fd(_err_fd, "err_fd");
    }
    _err_fd = fd;
}

void VirtQueue::set_vring_addr(
    const AddressTranslator& translate, const vhost_vring_addr& vra
) {
    _ring.set_addr(translate, vra);

    /*
     * Fresh (or reconnecting) rings start with used->idx already reflecting
     * how far the device had progressed; adopt it so that our next push()
     * publishes at the correct position instead of clobbering entries the
     * driver has not consumed yet.
     */
    _used_idx = RAWSTD_LE16TOH(_ring.used_idx());

    /*
     * The driver's used_event in this (possibly brand new) ring memory
     * cannot be assumed consistent with our freshly-adopted _used_idx;
     * force the next completion to notify unconditionally rather than
     * risk should_notify() silently agreeing to skip it forever.
     */
    _signalled_used_valid = false;
}

void VirtQueue::set_enabled(bool enabled) {
    if (enabled) {
        if (_enable_count++ > 0) {
            return;
        }

        prime_call_fd();
        arm_kick();
        return;
    }

    if (_enable_count == 0) {
        return;
    }

    if (--_enable_count > 0) {
        return;
    }

    if (_kick_fd != -1) {
        int res = rawio_cancel_all(_queue, _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vhost: failed to cancel pending kick_fd ops: %s\n",
                strerror(-res)
            );
        }
        _kick_armed = false;
    }
}

std::unique_ptr<DescChain> VirtQueue::pop(const Device& device) {
    std::unique_ptr<DescChain> chain =
        pop([&device](uint64_t addr) { return device.guest_phys_to_va(addr); });

    /*
     * Mirrors libvhost-user's vu_queue_pop(): with EVENT_IDX negotiated,
     * the device must tell the driver (via avail_event, the used ring's
     * counterpart to used_event) not to bother kicking again until
     * last_avail_idx has moved past this point. Without this, the driver
     * may legitimately decide -- based on its own EVENT_IDX arithmetic
     * against a stale avail_event -- that a later kick is unnecessary,
     * and we would then wait forever for a kick that never comes.
     */
    if (chain && device.event_idx_negotiated()) {
        _ring.set_avail_event(RAWSTD_LE16TOH(_last_avail_idx));
    }

    return chain;
}

std::unique_ptr<DescChain> VirtQueue::pop(const AddressTranslator& translate) {
    unsigned int num = _ring.num();
    if (num == 0 || !_ring.mapped()) {
        return nullptr;
    }

    uint16_t avail_idx = RAWSTD_LE16TOH(_ring.avail_idx());
    if (_last_avail_idx == avail_idx) {
        return nullptr;
    }

    uint16_t head = RAWSTD_LE16TOH(_ring.avail_ring(_last_avail_idx));
    _last_avail_idx = static_cast<uint16_t>(_last_avail_idx + 1);

    if (head >= num) {
        throw std::runtime_error("vhost: descriptor head out of range");
    }

    std::unique_ptr<DescChain> chain = std::make_unique<DescChain>();
    chain->head = head;

    const vring_desc* table = nullptr;
    unsigned int table_size = num;
    bool indirect = false;
    uint16_t idx = head;

    for (unsigned int steps = 0;; ++steps) {
        if (steps > table_size) {
            throw std::runtime_error(
                "vhost: descriptor chain too long or cyclic"
            );
        }

        vring_desc d = indirect ? table[idx] : _ring.desc(idx);
        uint16_t flags = RAWSTD_LE16TOH(d.flags);

        if (flags & VRING_DESC_F_INDIRECT) {
            if (indirect) {
                throw std::runtime_error(
                    "vhost: nested indirect descriptors are not allowed"
                );
            }

            uint32_t len = RAWSTD_LE32TOH(d.len);
            if (len == 0 || len % sizeof(vring_desc) != 0) {
                throw std::runtime_error(
                    "vhost: invalid indirect descriptor table length"
                );
            }

            uint64_t addr = RAWSTD_LE64TOH(d.addr);
            void* va = translate(addr);
            if (va == nullptr) {
                throw std::runtime_error(
                    "vhost: invalid indirect descriptor table address"
                );
            }

            table = static_cast<const vring_desc*>(va);
            table_size = len / sizeof(vring_desc);
            indirect = true;
            idx = 0;
            steps = 0;
            continue;
        }

        uint64_t addr = RAWSTD_LE64TOH(d.addr);
        uint32_t len = RAWSTD_LE32TOH(d.len);

        if (len > 0) {
            void* va = translate(addr);
            if (va == nullptr) {
                throw std::runtime_error("vhost: invalid descriptor address");
            }

            iovec iov;
            iov.iov_base = va;
            iov.iov_len = len;

            if (flags & VRING_DESC_F_WRITE) {
                chain->writable.push_back(iov);
            } else {
                chain->readable.push_back(iov);
            }
        }

        if (!(flags & VRING_DESC_F_NEXT)) {
            break;
        }

        idx = RAWSTD_LE16TOH(d.next);
        if (idx >= table_size) {
            throw std::runtime_error("vhost: descriptor next out of range");
        }
    }

    return chain;
}

void VirtQueue::push(uint16_t head, uint32_t len) {
    uint16_t pos = _used_idx;

    _ring.set_used(
        pos, RAWSTD_LE32TOH(static_cast<uint32_t>(head)), RAWSTD_LE32TOH(len)
    );

    _used_idx = static_cast<uint16_t>(_used_idx + 1);

    /*
     * Publish the new used->idx only after the used ring entry above is
     * visible: the driver may start reading as soon as it observes idx
     * change.
     */
    __sync_synchronize();
    _ring.set_used_idx(RAWSTD_LE16TOH(_used_idx));
}

bool VirtQueue::should_notify(bool event_idx_negotiated) noexcept {
    /*
     * Make sure we observe the driver's latest avail->flags / used_event
     * before deciding whether to skip the notification.
     */
    __sync_synchronize();

    if (event_idx_negotiated) {
        bool was_valid = _signalled_used_valid;
        _signalled_used_valid = true;

        if (!was_valid) {
            return true;
        }

        uint16_t event = RAWSTD_LE16TOH(_ring.used_event());
        uint16_t new_idx = _used_idx;
        uint16_t old_idx = static_cast<uint16_t>(_used_idx - 1);
        return static_cast<uint16_t>(new_idx - event - 1) <
               static_cast<uint16_t>(new_idx - old_idx);
    }

    return !(RAWSTD_LE16TOH(_ring.avail_flags()) & VRING_AVAIL_F_NO_INTERRUPT);
}

void VirtQueue::notify(bool event_idx_negotiated) {
    if (_call_fd == -1) {
        rawstd_debug("vhost: notify: no call_fd, skipping\n");
        return;
    }

    if (!should_notify(event_idx_negotiated)) {
        rawstd_debug("vhost: notify: should_notify() is false, skipping\n");
        return;
    }

    rawstd_debug("vhost: notify: writing call_fd %d\n", _call_fd);

    std::unique_ptr<NotifyCtx> ctx = std::make_unique<NotifyCtx>();
    ctx->value = 1;

    int res = rawio_write(
        _queue, _call_fd, &ctx->value, sizeof(ctx->value), notify_cb, ctx.get()
    );
    if (res) {
        rawstd_error("vhost: failed to notify call_fd: %s\n", strerror(-res));
        return;
    }

    ctx.release();
}

} // namespace vhost
} // namespace rawstor
