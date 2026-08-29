#include <vduse/virtqueue.hpp>

#include "device.hpp"

#include <stdheaders/linux/virtio_ring.h>

#include <rawstd/coro.hpp>
#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/rawio.h>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

// ---------------------------------------------------------------------
// This file owns two things: the ring mechanism (set_vring_size/
// set_vring_base/set_vring_addr(AddressTranslator, ...)/pop/push/
// should_notify, plain and synchronous), and the cross-thread *policy*
// that lets Device's control-plane thread safely reach a VirtQueue that
// owns and is driven by its own OS thread:
//
//   - post_*()/get_vq_state()/pause()/resume(), called only from the
//     control-plane thread on a running() VirtQueue, enqueue a Command
//     into `_cmds` (guarded by `_cmd_mutex`) and wake the owning thread's
//     reactor via a self-pipe (`_wake_pipe`, a rawstd::Pipe -- a plain
//     pipe rather than eventfd(), matching CLAUDE.md's portability
//     guidance outside librawio's io_uring backend). get_vq_state()/
//     pause() additionally block on a std::promise/future pair
//     (Reply<T>) until the owning thread has actually applied the
//     command -- acceptable only because both are rare, off-the-hot-path
//     control-plane operations.
//   - The owning thread's reactor (_run(), in virtqueue_worker.cpp) keeps
//     a read armed on `_wake_pipe`'s read end via this same VirtQueue's
//     own `_queue`, mirroring kick_fd's arm_kick()/kick_cb rearm pattern
//     below. Each wakeup drains and applies every queued Command in
//     order (drain_commands()/_apply()), then rearms.
//
// Every _apply() overload runs exclusively on the owning thread, so it's
// free to touch `_kick_fd`/`_queue` et al. directly with no locking of
// its own -- the whole point of routing through the command queue is
// that nothing else ever does. Mirrors vhost/src/virtqueue.cpp almost
// verbatim; see there for the design this is adapted from.
// ---------------------------------------------------------------------

namespace {

using rawstor::vduse::Device;
using rawstor::vduse::VirtQueue;

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
        rawstd_error("vduse: kick_fd read failed: %s\n", strerror(-result));
        return 0;
    }

    if (static_cast<size_t>(result) != sizeof(ctx->value)) {
        rawstd_error("vduse: unexpected kick_fd read size: %zd\n", result);
        return 0;
    }

    VirtQueue* vq = ctx->vq;

    try {
        vq->process_queue();
    } catch (const std::exception& e) {
        rawstd_error("vduse: error processing virtqueue: %s\n", e.what());
    }

    try {
        vq->arm_kick();
    } catch (const std::exception& e) {
        rawstd_error("vduse: failed to rearm kick_fd: %s\n", e.what());
    }

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
        rawstd_error("vduse: wake_fd read failed: %s\n", strerror(-result));
        return 0;
    }

    VirtQueue* vq = ctx->vq;

    vq->drain_commands();

    try {
        vq->arm_wake();
    } catch (const std::exception& e) {
        rawstd_error("vduse: failed to rearm wake_fd: %s\n", e.what());
    }

    return 0;
}

} // namespace

namespace rawstor {
namespace vduse {

VirtQueue::~VirtQueue() {
    if (running()) {
        stop();
    }

    if (_kick_fd != -1) {
        close_fd(_kick_fd, "kick_fd");
    }
    // _wake_pipe closes both its own ends itself (rawstd::Pipe's
    // destructor) if start() ever created it.
}

void VirtQueue::start(const std::string& target, unsigned int queue_size) {
    _wake_pipe.emplace();

    std::promise<void> ready;
    std::future<void> ready_future = ready.get_future();

    // SIGINT/SIGTERM are process-wide: the kernel delivers them to some
    // arbitrary thread that doesn't have them blocked, which could just
    // as well be this new worker thread as the control-plane thread that
    // actually knows how to act on them. Block every signal on this
    // (control-plane) thread before spawning, so the child inherits an
    // all-blocked mask, then restore this thread's own mask right after
    // -- standard "spawn workers with signals blocked" idiom, mirroring
    // vhost::VirtQueue::start().
    sigset_t all_signals, old_mask;
    sigfillset(&all_signals);
    pthread_sigmask(SIG_BLOCK, &all_signals, &old_mask);

    _thread = std::thread(
        &VirtQueue::_run, this, target, queue_size, std::move(ready)
    );

    pthread_sigmask(SIG_SETMASK, &old_mask, nullptr);

    // Propagates whatever exception _run() hit trying to create
    // _queue/_object -- in which case _run() has already returned (the
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
    _post(Shutdown{});
    _thread.join();
}

void VirtQueue::_post(Command cmd) {
    {
        std::lock_guard<std::mutex> lock(_cmd_mutex);
        _cmds.push_back(std::move(cmd));
    }
    char b = 1;
    // Best effort: the pipe is non-blocking and its buffer is many
    // orders of magnitude larger than the command traffic this ever
    // sees, so EAGAIN here just means a wakeup byte from an earlier
    // _post() is already pending -- the command we just enqueued will
    // still be drained by the wakeup that byte causes, so it's not an
    // error, merely redundant.
    ssize_t res = write(_wake_pipe->write_fd(), &b, 1);
    if (res == -1 && errno != EAGAIN) {
        rawstd_error(
            "vduse: failed to wake virtqueue worker: %s\n", strerror(errno)
        );
    }
    errno = 0;
}

void VirtQueue::post_set_vring_size(unsigned int size) {
    _post(SetVringSize{size});
}

void VirtQueue::post_set_vring_addr(
    uint64_t desc_addr, uint64_t driver_addr, uint64_t device_addr
) {
    _post(SetVringAddr{desc_addr, driver_addr, device_addr});
}

void VirtQueue::post_set_kick_fd(int fd) {
    _post(SetKickFd{fd});
}

void VirtQueue::post_set_enabled(bool enabled) {
    _post(SetEnabled{enabled});
}

void VirtQueue::post_retranslate() {
    _post(Retranslate{});
}

uint16_t VirtQueue::get_vq_state() {
    GetVqState cmd;
    std::future<uint16_t> f = cmd.reply.promise.get_future();
    _post(std::move(cmd));
    return f.get();
}

void VirtQueue::pause() {
    Pause cmd;
    std::future<void> f = cmd.reply.promise.get_future();
    _post(std::move(cmd));
    f.get();
}

void VirtQueue::resume() {
    _post(Resume{});
}

void VirtQueue::post_run(std::function<void()> fn) {
    _post(RunTask{std::move(fn)});
}

void VirtQueue::drain_commands() {
    std::deque<Command> local;
    {
        std::lock_guard<std::mutex> lock(_cmd_mutex);
        local.swap(_cmds);
    }
    for (Command& cmd : local) {
        std::visit([this](auto&& c) { _apply(std::move(c)); }, std::move(cmd));
    }
}

void VirtQueue::_apply(SetVringSize&& cmd) {
    set_vring_size(cmd.size);
}

void VirtQueue::_apply(SetVringAddr&& cmd) {
    Device& device = *_device;
    set_vring_addr(
        [&device](uint64_t iova) { return device.iova_to_va(iova); },
        cmd.desc_addr, cmd.driver_addr, cmd.device_addr
    );
}

void VirtQueue::_apply(SetKickFd&& cmd) {
    _set_kick_fd(cmd.fd);
}

void VirtQueue::_apply(SetEnabled&& cmd) {
    _set_enabled(cmd.enabled);
}

void VirtQueue::_apply(Retranslate&& /*cmd*/) {
    if (!_ring.mapped()) {
        return;
    }
    Device& device = *_device;
    _ring.retranslate([&device](uint64_t iova) {
        return device.iova_to_va(iova);
    });
}

void VirtQueue::_apply(GetVqState&& cmd) {
    cmd.reply.promise.set_value(_last_avail_idx);
}

void VirtQueue::_apply(Pause&& cmd) {
    _paused = true;
    if (_inflight == 0) {
        cmd.reply.promise.set_value();
    } else {
        _pending_pauses.push_back(std::move(cmd.reply));
    }
}

void VirtQueue::_apply(Resume&& /*cmd*/) {
    _paused = false;
    try {
        process_queue();
    } catch (const std::exception& e) {
        rawstd_error("vduse: error processing virtqueue: %s\n", e.what());
    }
}

void VirtQueue::_apply(RunTask&& cmd) {
    // `fn` may itself launch a DetachedTask (e.g. flush_object_task()
    // via post_run(), see virtqueue_worker.cpp's flush_task()) --
    // rethrow whatever it left pending, same as every other _apply()
    // overload that can.
    cmd.fn();
    rawstd::DetachedTask::rethrow_if_pending();
}

void VirtQueue::_apply(Shutdown&& /*cmd*/) {
    _stop_requested = true;
}

void VirtQueue::arm_kick() {
    rawstd_debug(
        "vduse: arm_kick(vq=%zu): kick_armed=%d kick_fd=%d\n", _index,
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

    int res = rawio_read(
        _queue, _wake_pipe->read_fd(), &ctx->byte, 1, wake_cb, ctx.get()
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    ctx.release();
}

void VirtQueue::_set_kick_fd(int fd) {
    if (_kick_fd != -1) {
        int res = rawio_cancel_all(_queue, _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vduse: failed to cancel pending kick_fd ops: %s\n",
                strerror(-res)
            );
        }
        close_fd(_kick_fd, "kick_fd");
    }

    _kick_fd = fd;
    _kick_armed = false;

    if (_enabled && _kick_fd != -1) {
        arm_kick();
    }
}

void VirtQueue::_set_enabled(bool enabled) {
    if (enabled == _enabled) {
        return;
    }
    _enabled = enabled;

    if (enabled) {
        if (_kick_fd != -1) {
            arm_kick();
        }
        return;
    }

    // vduse always tears kick_fd and the ring mapping fully down on
    // disable (unlike vhost-user, which may toggle SET_VRING_ENABLE
    // without a fresh SET_VRING_KICK/SET_VRING_ADDR) -- mirrors the
    // pre-multiqueue single-threaded Device::_disable_queue()'s own
    // close_kick_fd()+clear_vring_addr() sequence, just applied here on
    // this VirtQueue's own thread instead of directly from the
    // control-plane thread.
    if (_kick_fd != -1) {
        int res = rawio_cancel_all(_queue, _kick_fd);
        if (res && res != -ENOENT) {
            rawstd_error(
                "vduse: failed to cancel pending kick_fd ops: %s\n",
                strerror(-res)
            );
        }
        close_fd(_kick_fd, "kick_fd");
        _kick_fd = -1;
    }
    _kick_armed = false;
    clear_vring_addr();
}

void VirtQueue::set_vring_addr(
    const AddressTranslator& translate, uint64_t desc_addr,
    uint64_t driver_addr, uint64_t device_addr
) {
    _ring.set_addr(translate, desc_addr, driver_addr, device_addr);

    /*
     * A fresh ring's used->idx already reflects how far the device had
     * progressed (relevant across a VDUSE_UPDATE_IOTLB remap, not just
     * initial setup); adopt it so our next push() publishes at the
     * correct position instead of clobbering entries the driver hasn't
     * consumed yet.
     */
    _used_idx = RAWSTD_LE16TOH(_ring.used_idx());

    /*
     * The driver's used_event in this (possibly remapped) ring memory
     * cannot be assumed consistent with our freshly-adopted _used_idx;
     * force the next completion to notify unconditionally.
     */
    _signalled_used_valid = false;
}

std::unique_ptr<DescChain> VirtQueue::pop(Device& device) {
    std::unique_ptr<DescChain> chain =
        pop([&device](uint64_t iova) { return device.iova_to_va(iova); });

    /*
     * Mirrors vhost::VirtQueue::pop(const Device&): with EVENT_IDX
     * negotiated, the device must tell the driver (via avail_event) not
     * to bother kicking again until last_avail_idx has moved past this
     * point.
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
        throw std::runtime_error("vduse: descriptor head out of range");
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
                "vduse: descriptor chain too long or cyclic"
            );
        }

        vring_desc d = indirect ? table[idx] : _ring.desc(idx);
        uint16_t flags = RAWSTD_LE16TOH(d.flags);

        if (flags & VRING_DESC_F_INDIRECT) {
            if (indirect) {
                throw std::runtime_error(
                    "vduse: nested indirect descriptors are not allowed"
                );
            }

            uint32_t len = RAWSTD_LE32TOH(d.len);
            if (len == 0 || len % sizeof(vring_desc) != 0) {
                throw std::runtime_error(
                    "vduse: invalid indirect descriptor table length"
                );
            }

            uint64_t addr = RAWSTD_LE64TOH(d.addr);
            void* va = translate(addr);
            if (va == nullptr) {
                throw std::runtime_error(
                    "vduse: invalid indirect descriptor table address"
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
                throw std::runtime_error("vduse: invalid descriptor address");
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
            throw std::runtime_error("vduse: descriptor next out of range");
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

void VirtQueue::notify(Device& device, bool event_idx_negotiated) {
    if (!should_notify(event_idx_negotiated)) {
        rawstd_debug("vduse: notify: should_notify() is false, skipping\n");
        return;
    }

    rawstd_debug("vduse: notify: injecting irq for vq %zu\n", _index);

    device.inject_irq(_index);
}

} // namespace vduse
} // namespace rawstor
