#include "device.hpp"

#include <stdheaders/linux/virtio_blk.h>
#include <stdheaders/linux/virtio_config.h>
#include <stdheaders/linux/virtio_ring.h>
#include <vhost/user_protocol.h>

#include <rawstd/coro.hpp>
#include <rawstd/endian.h>
#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <rawstor/object.h>
#include <rawstor/rawio.h>
#include <rawstor/target.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <fcntl.h>

#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// The version of the protocol we support
#define VHOST_USER_VERSION 1

/* VhostSetConfigType: who is asking to change the config space. */
#define VHOST_SET_CONFIG_TYPE_FRONTEND 0

#define VIRTIO_BLK_SECTOR_BITS 9

namespace {

// One vhost-user control message's worth of state: the request header,
// its (union-typed) payload, and any fds carried alongside it. A stack
// local of the coroutine driving dispatch_loop() below -- unlike
// ost/src/client.cpp's analogous per-request state, nothing here needs to
// outlive a single loop iteration or be shared across concurrently
// in-flight operations, so this is a plain reference-bound aggregate, not
// a heap-allocated, shared_ptr-tracked object.
class DeviceOp {
private:
    rawstor::vhost::Device& _device;
    VhostUserHeader _header;
    VhostUserPayload _payload;
    VhostUserFds _fds;

public:
    DeviceOp(rawstor::vhost::Device& device) : _device(device) {}
    DeviceOp(const DeviceOp&) = delete;
    DeviceOp(DeviceOp&&) = delete;
    DeviceOp& operator=(const DeviceOp&) = delete;
    DeviceOp& operator=(DeviceOp&&) = delete;

    inline rawstor::vhost::Device& device() noexcept { return _device; }

    inline VhostUserHeader& header() noexcept { return _header; }

    inline VhostUserPayload& payload() noexcept { return _payload; }

    inline VhostUserFds& fds() noexcept { return _fds; }
};

// ---------------------------------------------------------------------
// rawstd::CallbackAwaitable<size_t> bridge over the control path's
// rawio.h ops -- rawio_read()/rawio_recvmsg()/rawio_sendmsg() all share
// the same ssize_t result/data callback shape, so a single trampoline
// suffices for all three co_*() wrappers below. See
// rawstd::CallbackAwaitable<T>'s own doc comment for the general shape
// this follows, and this file's own io_trampoline() (over the data
// path's rawstor_object_*() ops) for why this one is named
// differently despite the similar role -- distinct C callback shapes,
// distinct bridges, one per file convention throughout this codebase.
// ---------------------------------------------------------------------

int rawio_trampoline(ssize_t result, void* data) {
    size_t value = result < 0 ? 0 : static_cast<size_t>(result);
    int error = result < 0 ? static_cast<int>(-result) : 0;
    static_cast<rawstd::CallbackAwaitable<size_t>*>(data)->complete(
        value, error
    );
    return 0;
}

rawstd::Task<size_t>
co_read(RawIOQueue* queue, int fd, void* buf, size_t size) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_read(queue, fd, buf, size, rawio_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t>
co_recvmsg(RawIOQueue* queue, int fd, msghdr* msg, unsigned int flags) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_recvmsg(queue, fd, msg, flags, rawio_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

rawstd::Task<size_t>
co_sendmsg(RawIOQueue* queue, int fd, msghdr* msg, unsigned int flags) {
    rawstd::CallbackAwaitable<size_t> awaiter;
    int res = rawio_sendmsg(queue, fd, msg, flags, rawio_trampoline, &awaiter);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_return co_await awaiter;
}

// Wakes Device::loop() out of a blocking rawio_wait() reliably on the
// first SIGINT/SIGTERM, the same way dispatch_loop() below wakes it on a
// clean disconnect: written to by main.cpp's sact_handler (via Server's
// own wake_fd), read back here and folded into the very `done` flag
// dispatch_loop() itself sets, so loop()'s pump doesn't need to
// distinguish why it's stopping. See Device's own constructor doc
// comment for why relying on rawio_wait()'s -EINTR alone isn't enough.
rawstd::DetachedTask wake_task(RawIOQueue* queue, int wake_fd, bool& done) {
    char buf[1];
    co_await co_read(queue, wake_fd, buf, sizeof(buf));
    done = true;
}

// Fire-and-forget notification -- unlike every reply above, nothing
// awaits this (it's a best-effort "in case of I/O hang after
// reconnecting" poke, not part of the request/response flow itself), so
// a failure is logged and otherwise ignored rather than torn down
// through dispatch_loop()'s own error handling.
int notify_eventfd_cb(ssize_t result, void* data) {
    std::unique_ptr<uint64_t> value(static_cast<uint64_t*>(data));
    if (result < 0) {
        rawstd_error("Failed to notify eventfd: %s\n", strerror(-result));
    } else if (static_cast<size_t>(result) != sizeof(*value)) {
        rawstd_error("Unexpected eventfd write size: %zd\n", result);
    }
    return 0;
}

void notify_eventfd(RawIOQueue* queue, int fd, uint64_t value) {
    auto v = std::make_unique<uint64_t>(value);
    uint64_t* buf = v.get();
    int res =
        rawio_write(queue, fd, buf, sizeof(*buf), notify_eventfd_cb, v.get());
    if (res < 0) {
        rawstd_error("Failed to notify eventfd: %s\n", strerror(-res));
        return;
    }
    v.release();
}

// A reply message's wire-format builder: computes the header/payload/fds
// iovec+control-buffer shape for one vhost-user response, ready for
// dispatch_loop() to co_await co_sendmsg() with. No longer a Task
// subclass (there's nothing left to bridge to a C callback here --
// dispatch_loop() sends and validates it directly), so only str() (for
// the debug trace) is a customization point; msg()/size()/flags() are
// the same for every reply shape.
class Reply {
private:
    iovec _iov[2];
    char _control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))];
    msghdr _msg;

public:
    Reply(DeviceOp& op, size_t payload_size, uint32_t flags, int nfds) :
        _iov{
            {
                .iov_base = &op.header(),
                .iov_len = sizeof(op.header()),
            },
            {
                .iov_base = &op.payload(),
                .iov_len = payload_size,
            }
        },
        _control{},
        _msg{
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov,
            .msg_iovlen = 2,
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        } {
        if (_iov[1].iov_len == 0) {
            _msg.msg_iovlen = 1;
        }

        VhostUserHeader& header = op.header();

        header.flags = flags;
        header.flags &= ~VHOST_USER_VERSION_MASK;
        header.flags |= VHOST_USER_VERSION;
        header.flags |= VHOST_USER_REPLY_MASK;

        header.size = payload_size;

        const VhostUserFds& fds = op.fds();
        assert(nfds <= VHOST_MEMORY_BASELINE_NREGIONS);
        if (nfds > 0) {
            size_t fdsize = nfds * sizeof(int);
            _msg.msg_controllen = CMSG_SPACE(fdsize);
            _msg.msg_control = &_control;
            struct cmsghdr* cmsg = CMSG_FIRSTHDR(&_msg);
            cmsg->cmsg_len = CMSG_LEN(fdsize);
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            memcpy(CMSG_DATA(cmsg), fds.fds, fdsize);
        }
    }

    Reply(const Reply&) = delete;
    Reply(Reply&&) = delete;
    virtual ~Reply() = default;

    Reply& operator=(const Reply&) = delete;
    Reply& operator=(Reply&&) = delete;

    inline msghdr* msg() noexcept { return &_msg; }

    size_t size() const noexcept { return _iov[0].iov_len + _iov[1].iov_len; }

    inline int flags() const noexcept { return RAWSTD_MSG_NOSIGNAL; }

    virtual std::string str() const = 0;
};

class EmptyReply : public Reply {
public:
    EmptyReply(DeviceOp& op) : Reply(op, 0, 0, 0) {}

    std::string str() const override { return "empty"; }
};

class U64Reply : public Reply {
private:
    DeviceOp& _op;

public:
    U64Reply(DeviceOp& op, uint64_t value) :
        Reply(op, sizeof(op.payload().u64), 0, 0),
        _op(op) {
        VhostUserPayload& payload = _op.payload();

        payload.u64 = value;
    }

    std::string str() const override {
        std::ostringstream oss;
        oss << "u64: 0x" << std::hex << _op.payload().u64;
        return oss.str();
    }
};

class StateReply : public Reply {
private:
    DeviceOp& _op;

public:
    StateReply(DeviceOp& op, const vhost_vring_state& state) :
        Reply(op, sizeof(op.payload().state), 0, 0),
        _op(op) {
        VhostUserPayload& payload = _op.payload();

        payload.state = state;
    }

    std::string str() const override {
        std::ostringstream oss;
        const vhost_vring_state& state = _op.payload().state;
        oss << "state(index=" << state.index << ", num=" << state.num << ")";
        return oss.str();
    }
};

class InflightReply : public Reply {
private:
    DeviceOp& _op;

public:
    InflightReply(DeviceOp& op, const VhostUserInflight& inflight, int fd) :
        Reply(op, sizeof(op.payload().inflight), 0, set_fd(op, fd)),
        _op(op) {
        _op.payload().inflight = inflight;
    }

    std::string str() const override {
        std::ostringstream oss;
        const VhostUserInflight& inflight = _op.payload().inflight;
        oss << "inflight(mmap_size=" << inflight.mmap_size
            << ", mmap_offset=" << inflight.mmap_offset << ")";
        return oss.str();
    }

private:
    // Reply's constructor copies the fds to send from op.fds().
    static int set_fd(DeviceOp& op, int fd) {
        op.fds().fds[0] = fd;
        return 1;
    }
};

class ConfigReply : public Reply {
private:
    DeviceOp& _op;

public:
    ConfigReply(DeviceOp& op, const virtio_blk_config& config) :
        Reply(op, op.header().size, 0, 0),
        _op(op) {
        VhostUserPayload& payload = _op.payload();
        assert(payload.config.size <= sizeof(virtio_blk_config));

        memcpy(payload.config.region, &config, payload.config.size);
    }

    std::string str() const override {
        std::ostringstream oss;
        VhostUserPayload& payload = _op.payload();

        oss << "config(" << payload.config.size << ")";
        return oss.str();
    }
};

class MemRegReply : public Reply {
private:
    DeviceOp& _op;

public:
    MemRegReply(DeviceOp& op, const VhostUserMemRegMsg& msg) :
        Reply(op, sizeof(MemRegReply), 0, 0),
        _op(op) {
        VhostUserPayload& payload = _op.payload();

        payload.memreg = msg;
    }

    std::string str() const override { return "memreg"; }
};

void close_fds(VhostUserFds& fds) {
    for (unsigned int i = 0; i < fds.fd_num; ++i) {
        close(fds.fds[i]);
    }
}

/**
 * Get from the underlying vhost implementation the features bitmask. Feature
 * bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
 * VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
 */
std::unique_ptr<Reply> get_features(DeviceOp& op) {
    return std::make_unique<U64Reply>(op, op.device().get_features());
}

/**
 * Enable features in the underlying vhost implementation using a bitmask.
 * Feature bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
 * VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
 */
std::unique_ptr<Reply> set_features(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();

    op.device().set_features(payload.u64);

    return nullptr;
}

/**
 * Issued when a new connection is established. It marks the sender as the
 * front-end that owns of the session. This can be used on the back-end as a
 * "session start" flag.
 */
std::unique_ptr<Reply> set_owner(DeviceOp&) {
    return nullptr;
}

/**
 * Set the size of the queue.
 */
std::unique_ptr<Reply> set_vring_num(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();

    unsigned int index = payload.state.index;
    unsigned int num = payload.state.num;

    rawstd_debug("State.index: %u\n", index);
    rawstd_debug("State.num:   %u\n", num);

    op.device().set_vring_size(index, num);

    return nullptr;
}

/**
 * Sets the addresses of the different aspects of the vring.
 */
std::unique_ptr<Reply> set_vring_addr(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();
    const vhost_vring_addr& vra = payload.addr;

    rawstd_debug("vhost_vring_addr:\n");
    rawstd_debug("    index:  %d\n", vra.index);
    rawstd_debug("    flags:  %d\n", vra.flags);
    rawstd_debug(
        "    desc_user_addr:   0x%llx\n", (unsigned long long)vra.desc_user_addr
    );
    rawstd_debug(
        "    used_user_addr:   0x%llx\n", (unsigned long long)vra.used_user_addr
    );
    rawstd_debug(
        "    avail_user_addr:  0x%llx\n",
        (unsigned long long)vra.avail_user_addr
    );
    rawstd_debug(
        "    log_guest_addr:   0x%llx\n", (unsigned long long)vra.log_guest_addr
    );

    op.device().set_vring_addr(vra);

    return nullptr;
}

/**
 * Sets the next index to use for descriptors in this vring.
 */
std::unique_ptr<Reply> set_vring_base(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();

    unsigned int index = payload.state.index;
    unsigned int num = payload.state.num;

    rawstd_debug("State.index: %u\n", index);
    rawstd_debug("State.num:   %u\n", num);

    op.device().set_vring_base(index, num);

    return nullptr;
}

/**
 * Set the event file descriptor for adding buffers to the vring. It is passed
 * in the ancillary data.
 */
std::unique_ptr<Reply> set_vring_kick(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    const VhostUserPayload& payload = op.payload();
    VhostUserFds& fds = op.fds();

    int index = payload.u64 & VHOST_USER_VRING_IDX_MASK;
    bool nofd = payload.u64 & VHOST_USER_VRING_NOFD_MASK;
    int fd = nofd ? -1 : fds.fds[0];

    rawstd_debug("Got kick_fd: %d for vq: %d\n", fd, index);

    if (nofd) {
        close_fds(fds);
    }

    if (fds.fd_num != 1 && !nofd) {
        rawstd_error("Invalid fds in request: %d", header.request);
        close_fds(fds);
        return nullptr;
    }

    try {
        op.device().set_vring_kick(index, fd);
    } catch (...) {
        if (fd != -1) {
            close(fd);
        }
        throw;
    }

    return nullptr;
}

/**
 * Set the event file descriptor to signal when buffers are used. It is passed
 * in the ancillary data.
 */
std::unique_ptr<Reply> set_vring_call(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    const VhostUserPayload& payload = op.payload();
    VhostUserFds& fds = op.fds();

    int index = payload.u64 & VHOST_USER_VRING_IDX_MASK;
    bool nofd = payload.u64 & VHOST_USER_VRING_NOFD_MASK;
    int fd = nofd ? -1 : fds.fds[0];

    rawstd_debug("Got call_fd: %d for vq: %d\n", fd, index);

    if (nofd) {
        close_fds(fds);
    }

    if (fds.fd_num != 1 && !nofd) {
        rawstd_error("Invalid fds in request: %d", header.request);
        close_fds(fds);
        return nullptr;
    }

    try {
        op.device().set_vring_call(index, fd);
    } catch (...) {
        if (fd != -1) {
            close(fd);
        }
        throw;
    }

    // in case of I/O hang after reconnecting
    if (fd != -1) {
        op.device().notify_reconnect_hint(fd);
    }

    return nullptr;
}

/**
 * Set the event file descriptor to signal when error occurs. It is passed in
 * the ancillary data.
 */
std::unique_ptr<Reply> set_vring_err(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    const VhostUserPayload& payload = op.payload();
    VhostUserFds& fds = op.fds();

    int index = payload.u64 & VHOST_USER_VRING_IDX_MASK;
    bool nofd = payload.u64 & VHOST_USER_VRING_NOFD_MASK;
    int fd = nofd ? -1 : fds.fds[0];

    rawstd_debug("Got err_fd: %d for vq: %d\n", fd, index);

    if (nofd) {
        close_fds(fds);
    }

    if (fds.fd_num != 1 && !nofd) {
        rawstd_error("Invalid fds in request: %d", header.request);
        close_fds(fds);
        return nullptr;
    }

    try {
        op.device().set_vring_err(index, fd);
    } catch (...) {
        if (fd != -1) {
            close(fd);
        }
        throw;
    }

    return nullptr;
}

/**
 * Enables or disables processing of a virtqueue. Sent only when
 * VHOST_USER_PROTOCOL_F_MQ (or REPLY_ACK) negotiation requires explicit
 * start/stop of individual rings.
 */
std::unique_ptr<Reply> set_vring_enable(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();

    unsigned int index = payload.state.index;
    bool enable = payload.state.num != 0;

    rawstd_debug("State.index:  %u\n", index);
    rawstd_debug("State.enable: %u\n", enable);

    op.device().set_vring_enable(index, enable);

    return nullptr;
}

/**
 * Front-end requests the current vring base index, used before tearing down
 * or migrating a ring. The back-end must stop processing the ring and reply
 * with the index up to which it has consumed the avail ring.
 */
std::unique_ptr<Reply> get_vring_base(DeviceOp& op) {
    VhostUserPayload& payload = op.payload();

    unsigned int index = payload.state.index;

    vhost_vring_state state;
    state.index = index;
    state.num = op.device().get_vring_base(index);

    return std::make_unique<StateReply>(op, state);
}

/**
 * Get the protocol feature bitmask from the underlying vhost implementation.
 */
std::unique_ptr<Reply> get_protocol_features(DeviceOp& op) {
    return std::make_unique<U64Reply>(op, op.device().get_protocol_features());
}

/**
 * Enable protocol features in the underlying vhost implementation using a
 * bitmask.
 */
std::unique_ptr<Reply> set_protocol_features(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();

    rawstd_debug(
        "Setting features u64: 0x%llx\n", (unsigned long long)payload.u64
    );

    op.device().set_protocol_features(payload.u64);

    return nullptr;
}

/**
 * Query how many queues the back-end supports.
 */
std::unique_ptr<Reply> get_queue_num(DeviceOp& op) {
    return std::make_unique<U64Reply>(op, op.device().max_queues());
}

/**
 * Set the socket file descriptor for back-end initiated requests. It is
 * passed in the ancillary data.
 */
std::unique_ptr<Reply> set_backend_req_fd(DeviceOp& op) {
    VhostUserFds& fds = op.fds();

    if (fds.fd_num != 1) {
        rawstd_error("Invalid backend_req_fd message (%d fd's)", fds.fd_num);
        close_fds(fds);
        return nullptr;
    }

    rawstd_debug("Got backend_fd: %d\n", fds.fds[0]);
    op.device().set_backend_fd(fds.fds[0]);

    return nullptr;
}

/**
 * When VHOST_USER_PROTOCOL_F_CONFIG is negotiated, this message is submitted
 * by the vhost-user front-end to fetch the contents of the virtio device
 * configuration space.
 */
std::unique_ptr<Reply> get_config(DeviceOp& op) {
    const VhostUserPayload& payload = op.payload();
    if (payload.config.size > sizeof(virtio_blk_config)) {
        /**
         * Return zero to indicate an error to frontend
         */
        return std::make_unique<EmptyReply>(op);
    }

    return std::make_unique<ConfigReply>(op, op.device().get_config());
}

/**
 * The front-end updates a portion of the virtio device configuration space.
 */
std::unique_ptr<Reply> set_config(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    const VhostUserPayload& payload = op.payload();
    const VhostUserConfig& c = payload.config;

    bool need_reply = header.flags & VHOST_USER_NEED_REPLY_MASK;

    try {
        op.device().set_config(c.region, c.offset, c.size, c.flags);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return need_reply ? std::make_unique<U64Reply>(op, 1) : nullptr;
    }

    return need_reply ? std::make_unique<U64Reply>(op, 0) : nullptr;
}

/**
 * When the VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS protocol feature has
 * been successfully negotiated, this message is submitted by the front-end
 * to the back-end to learn the maximum number of memory slots it may expose
 * to the guest.
 */
std::unique_ptr<Reply> get_max_mem_slots(DeviceOp& op) {
    return std::make_unique<U64Reply>(op, op.device().get_max_mem_slots());
}

/**
 * Registers a new guest memory region with the back-end. Exactly one file
 * descriptor from which the memory is mapped is passed in the ancillary
 * data.
 */
std::unique_ptr<Reply> add_mem_reg(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    VhostUserPayload& payload = op.payload();
    VhostUserFds& fds = op.fds();

    VhostUserMemRegMsg& m = payload.memreg;

    if (fds.fd_num != 1) {
        rawstd_error(
            "VHOST_USER_ADD_MEM_REG received %d fds - only 1 fd "
            "should be sent for this message type",
            fds.fd_num
        );
        close_fds(fds);
        return nullptr;
    }

    if (header.size < sizeof(VhostUserMemoryRegion)) {
        rawstd_error(
            "VHOST_USER_ADD_MEM_REG requires a message size of at "
            "least %zu bytes and only %d bytes were received",
            sizeof(VhostUserMemoryRegion), header.size
        );
        close_fds(fds);
        return nullptr;
    }

    if (op.device().nregions() == VHOST_USER_MAX_RAM_SLOTS) {
        rawstd_error(
            "failing attempt to hot add memory via "
            "VHOST_USER_ADD_MEM_REG message because the backend has "
            "no free ram slots available"
        );
        close_fds(fds);
        return nullptr;
    }

    m.region.userspace_addr = op.device().add_mem_reg(m.region, fds.fds[0]);

    close(fds.fds[0]);

    rawstd_debug("Successfully added new region\n");

    return nullptr;
}

/**
 * Removes a guest memory region previously registered via
 * VHOST_USER_ADD_MEM_REG. Identified by guest physical address and size; the
 * file descriptor, if any is attached, is not used.
 */
/**
 * Front-end asks for shared memory to track in-flight descriptors in,
 * which it then keeps across back-end restarts and hands back via
 * VHOST_USER_SET_INFLIGHT_FD.
 */
std::unique_ptr<Reply> get_inflight_fd(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    VhostUserFds& fds = op.fds();

    if (fds.fd_num > 0) {
        close_fds(fds);
    }

    if (header.size != sizeof(VhostUserInflight)) {
        rawstd_error(
            "Invalid get_inflight_fd message size: %u\n",
            (unsigned int)header.size
        );
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    VhostUserInflight inflight = op.payload().inflight;
    rawstd_debug(
        "get_inflight_fd: num_queues=%u queue_size=%u\n",
        (unsigned int)inflight.num_queues, (unsigned int)inflight.queue_size
    );

    int fd = op.device().get_inflight_fd(
        inflight.num_queues, inflight.queue_size, inflight.mmap_size
    );
    inflight.mmap_offset = 0;

    return std::make_unique<InflightReply>(op, inflight, fd);
}

/**
 * Front-end hands back the in-flight memory it got from
 * VHOST_USER_GET_INFLIGHT_FD -- on every device start, including after
 * reconnecting to a restarted back-end.
 */
std::unique_ptr<Reply> set_inflight_fd(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    VhostUserFds& fds = op.fds();

    if (fds.fd_num != 1 || header.size != sizeof(VhostUserInflight)) {
        rawstd_error(
            "Invalid set_inflight_fd message size: %u fds: %u\n",
            (unsigned int)header.size, (unsigned int)fds.fd_num
        );
        close_fds(fds);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    const VhostUserInflight& inflight = op.payload().inflight;
    rawstd_debug(
        "set_inflight_fd: mmap_size=%" PRIu64 " mmap_offset=%" PRIu64
        " num_queues=%u queue_size=%u\n",
        inflight.mmap_size, inflight.mmap_offset,
        (unsigned int)inflight.num_queues, (unsigned int)inflight.queue_size
    );

    op.device().set_inflight_fd(
        fds.fds[0], inflight.mmap_size, inflight.mmap_offset,
        inflight.num_queues, inflight.queue_size
    );

    return nullptr;
}

std::unique_ptr<Reply> rem_mem_reg(DeviceOp& op) {
    const VhostUserHeader& header = op.header();
    VhostUserPayload& payload = op.payload();
    VhostUserFds& fds = op.fds();

    if (fds.fd_num > 0) {
        close_fds(fds);
    }

    if (header.size < sizeof(VhostUserMemoryRegion)) {
        rawstd_error(
            "VHOST_USER_REM_MEM_REG requires a message size of at "
            "least %zu bytes and only %d bytes were received",
            sizeof(VhostUserMemoryRegion), header.size
        );
        return nullptr;
    }

    op.device().rem_mem_reg(payload.memreg.region);

    return nullptr;
}

/**
 * Reset feature negotiation; sent rarely by modern front-ends. We simply
 * acknowledge it.
 */
std::unique_ptr<Reply> reset_owner(DeviceOp&) {
    return nullptr;
}

std::unique_ptr<Reply> response(DeviceOp& op) {
    switch (op.header().request) {
    case VHOST_USER_GET_FEATURES:
        return get_features(op);
    case VHOST_USER_SET_FEATURES:
        return set_features(op);
    case VHOST_USER_SET_OWNER:
        return set_owner(op);
    case VHOST_USER_RESET_OWNER:
        return reset_owner(op);
    case VHOST_USER_SET_VRING_NUM:
        return set_vring_num(op);
    case VHOST_USER_SET_VRING_ADDR:
        return set_vring_addr(op);
    case VHOST_USER_SET_VRING_BASE:
        return set_vring_base(op);
    case VHOST_USER_GET_VRING_BASE:
        return get_vring_base(op);
    case VHOST_USER_SET_VRING_KICK:
        return set_vring_kick(op);
    case VHOST_USER_SET_VRING_CALL:
        return set_vring_call(op);
    case VHOST_USER_SET_VRING_ERR:
        return set_vring_err(op);
    case VHOST_USER_SET_VRING_ENABLE:
        return set_vring_enable(op);
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        return get_protocol_features(op);
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        return set_protocol_features(op);
    case VHOST_USER_GET_QUEUE_NUM:
        return get_queue_num(op);
    case VHOST_USER_SET_BACKEND_REQ_FD:
        return set_backend_req_fd(op);
    case VHOST_USER_GET_CONFIG:
        return get_config(op);
    case VHOST_USER_SET_CONFIG:
        return set_config(op);
    case VHOST_USER_GET_MAX_MEM_SLOTS:
        return get_max_mem_slots(op);
    case VHOST_USER_ADD_MEM_REG:
        return add_mem_reg(op);
    case VHOST_USER_REM_MEM_REG:
        return rem_mem_reg(op);
    case VHOST_USER_GET_INFLIGHT_FD:
        return get_inflight_fd(op);
    case VHOST_USER_SET_INFLIGHT_FD:
        return set_inflight_fd(op);
    default:
        rawstd_error("Unexpected request: %d\n", op.header().request);
        throw std::runtime_error("Unexpected request");
    };
}

// Drives one vhost-user control connection's whole lifetime: loops
// reading one length-prefixed message at a time (header, then -- if
// header.size != 0 -- its payload), dispatching each to response() and
// co_awaiting the reply (if any) before reading the next message. No
// pipelining of reads-vs-replies here (unlike ost::Client's _recv_pump(),
// which fires off each command's I/O and keeps reading so a slow
// storage op doesn't stall the next request): every response() handler
// here is a synchronous, in-memory Device state mutation with no I/O of
// its own, so there is no slow op to pipeline around, and real front-ends
// (QEMU/libvhost-user) address this control channel strictly
// request-then-reply anyway -- sequential co_await is both simpler and a
// closer match to how it's actually used.
//
// Sets `done` (a Device::loop() stack local, safe to bind by reference:
// this coroutine is only ever resumed from inside a rawio_wait(queue)
// call Device::loop() itself makes, so its frame is guaranteed alive at
// that point) right before returning on a clean, message-boundary
// disconnect, so Device::loop()'s own pump knows to stop. Any other
// error (malformed input, a genuine I/O failure) is left to propagate as
// an unhandled exception out of this DetachedTask -- automatically
// rethrown the next time anything resumes a coroutine on this thread
// (see DetachedTask's own doc comment), which -- since this is the only
// coroutine Device::loop() drives -- is exactly the very rawio_wait()
// call that resumed this in the first place.
rawstd::DetachedTask dispatch_loop(
    RawIOQueue* queue, int fd, rawstor::vhost::Device& device, bool& done
) {
    while (true) {
        DeviceOp op(device);

        iovec iov{
            .iov_base = &op.header(),
            .iov_len = sizeof(op.header()),
        };
        char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))];
        msghdr msg{
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = control,
            .msg_controllen = sizeof(control),
            .msg_flags = 0,
        };

        size_t result = co_await co_recvmsg(queue, fd, &msg, MSG_WAITALL);
        if (result == 0) {
            // Front-end closed the connection at a message boundary: a
            // normal disconnect, not a malformed request.
            rawstd_info("Client disconnected: fd=%d\n", fd);
            done = true;
            co_return;
        }
        if (result != sizeof(op.header())) {
            rawstd_error("Unexpected request header size: %zu\n", result);
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        VhostUserFds& fds = op.fds();
        fds.fd_num = 0;
        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_RIGHTS) {
                size_t fd_size = cmsg->cmsg_len - CMSG_LEN(0);
                fds.fd_num = fd_size / sizeof(int);
                assert(fds.fd_num <= VHOST_MEMORY_BASELINE_NREGIONS);
                memcpy(fds.fds, CMSG_DATA(cmsg), fd_size);
                // A fd received via SCM_RIGHTS has no CLOEXEC of its own
                // (recvmsg() has no portable equivalent of Linux's
                // MSG_CMSG_CLOEXEC that also works on macOS) -- these
                // become kick_fd/call_fd/err_fd/backend_fd, all held for
                // the connection's lifetime, so without this a fork()
                // concurrent with this dispatch loop (e.g. the LVM/ZFS
                // storage backends shelling out to lvcreate/zfs/etc. via
                // src/subprocess.cpp) would leak them into that child.
                for (unsigned int i = 0; i < fds.fd_num; ++i) {
                    int res = rawstd_socket_set_cloexec(fds.fds[i]);
                    if (res < 0) {
                        RAWSTD_THROW_SYSTEM_ERROR(-res);
                    }
                }
                break;
            }
        }

        VhostUserHeader& header = op.header();
        if (header.size != 0) {
            if (header.size > sizeof(VhostUserPayload)) {
                rawstd_error(
                    "Unexpected request payload size: %u\n",
                    (unsigned int)header.size
                );
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
            size_t presult =
                co_await co_read(queue, fd, &op.payload(), header.size);
            if (presult != header.size) {
                rawstd_error("Unexpected request payload size: %zu\n", presult);
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
        }

        rawstd_debug("============= Vhost user message =============\n");
        rawstd_debug("Request: %d\n", header.request);
        rawstd_debug("Flags:   0x%x\n", header.flags);
        rawstd_debug("Size:    %u\n", header.size);
#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_DEBUG
        if (fds.fd_num) {
            std::ostringstream oss;
            for (unsigned int i = 0; i < fds.fd_num; i++) {
                oss << " " << fds.fds[i];
            }
            rawstd_debug("Fds:    %s\n", oss.str().c_str());
        }
#endif
        rawstd_debug("==============================================\n");

        bool need_reply = header.flags & VHOST_USER_NEED_REPLY_MASK;
        std::unique_ptr<Reply> reply = response(op);
        if (reply == nullptr && need_reply) {
            reply = std::make_unique<U64Reply>(op, 0);
        }
        if (reply != nullptr) {
            rawstd_debug("Sending back to guest: %s\n", reply->str().c_str());
            size_t sent =
                co_await co_sendmsg(queue, fd, reply->msg(), reply->flags());
            if (sent != reply->size()) {
                rawstd_error("Unexpected response size: %zu\n", sent);
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
            rawstd_debug("Message sent: %zu bytes\n", sent);
        }
    }
}

// Zeroed anonymous shared memory of `size` bytes the front-end can map
// too (it only ever receives the fd), for VHOST_USER_GET_INFLIGHT_FD.
int create_shm(size_t size) {
#if defined(RAWSTD_ON_LINUX)
    int fd =
        memfd_create("rawstor-vhost-inflight", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
#else
    static std::atomic<unsigned int> seq{0};
    std::ostringstream name;
    name << "/rawstor-vhost-inflight-" << getpid() << "-" << seq++;
    int fd = shm_open(name.str().c_str(), O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
    shm_unlink(name.str().c_str());
    int cres = rawstd_socket_set_cloexec(fd);
    if (cres < 0) {
        close(fd);
        RAWSTD_THROW_SYSTEM_ERROR(-cres);
    }
#endif

    if (ftruncate(fd, static_cast<off_t>(size))) {
        int errsv = errno;
        close(fd);
        RAWSTD_THROW_SYSTEM_ERROR(errsv);
    }

#if defined(RAWSTD_ON_LINUX)
    // The front-end can't resize it out from under our mapping.
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)) {
        int errsv = errno;
        close(fd);
        RAWSTD_THROW_SYSTEM_ERROR(errsv);
    }
#endif

    return fd;
}

size_t find_mem_region_pos(
    const std::vector<std::unique_ptr<rawstor::vhost::DevRegion>>& regions,
    const VhostUserMemoryRegion& m
) {
    if (regions.empty()) {
        return 0;
    }

    const uint64_t start_gpa = m.guest_phys_addr;
    const uint64_t end_gpa = start_gpa + m.memory_size;

    size_t low = 0;
    size_t high = regions.size() - 1;

    /**
     * We will add memory regions into the array sorted by GPA. Perform a
     * binary search to locate the insertion point: it will be at the low
     * index.
     */
    while (low <= high) {
        size_t mid = low + (high - low) / 2;
        const rawstor::vhost::DevRegion& cur = *regions[mid];

        // Overlap of GPA addresses.
        if (start_gpa < cur.guest_phys_addr() + cur.memory_size() &&
            cur.guest_phys_addr() < end_gpa) {
            throw std::runtime_error(
                "regions with overlapping guest physical addresses"
            );
        }

        if (start_gpa >= cur.guest_phys_addr() + cur.memory_size()) {
            low = mid + 1;
        }

        if (start_gpa < cur.guest_phys_addr()) {
            high = mid - 1;
        }
    }

    return low;
}

// Synchronous shim for Device's constructor: runs before loop() starts,
// i.e. never from inside dispatch_loop()'s own dispatch of `queue` --
// spinning `queue` here to wait for the callback is therefore safe,
// unlike doing so from a context that's itself already being dispatched
// by the same queue (see ost::Backend's own async close()/open()
// handling for that hazard, and virtqueue_worker.cpp's open_object()/
// close_object() for the equivalent shims each VirtQueue's own thread
// uses around its own RawstorObject). rawstor_target_spec() shares its
// ssize_t result callback shape (negative -> -errno, zero -> success)
// with rawstor_target_open()/rawstor_object_close(), but this file no
// longer calls either of those -- see rawstor/target.h's own doc comment
// for the general convention.
struct Result {
    int error = 0;
    bool done = false;
};

int result_cb(ssize_t result, void* data) {
    Result* r = static_cast<Result*>(data);
    r->error = result < 0 ? static_cast<int>(-result) : 0;
    r->done = true;
    return 0;
}

RawstorObjectSpec spec_object(RawIOQueue* queue, const std::string& target) {
    RawstorObjectSpec spec{};
    Result result;
    int res =
        rawstor_target_spec(queue, target.c_str(), &spec, result_cb, &result);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    while (!result.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-wres);
        }
    }
    if (result.error) {
        RAWSTD_THROW_SYSTEM_ERROR(result.error);
    }
    return spec;
}

} // namespace

namespace rawstor {
namespace vhost {

Device::Device(
    unsigned int queue_size, const std::string& target, int fd,
    bool write_cache_enabled, bool readonly, int wake_fd
) :
    _fd(fd),
    _queue(nullptr),
    _target(target),
    _queue_size(queue_size),
    _readonly(readonly),
    _vqs(MAX_QUEUES),
    _backend_fd(-1),
    _features(
        1ull << VIRTIO_BLK_F_SIZE_MAX | 1ull << VIRTIO_BLK_F_SEG_MAX |
        1ull << VIRTIO_BLK_F_BLK_SIZE | 1ull << VIRTIO_BLK_F_TOPOLOGY |
        1ull << VIRTIO_BLK_F_MQ | 1ull << VIRTIO_BLK_F_FLUSH |
        1ull << VIRTIO_BLK_F_CONFIG_WCE | 1ull << VIRTIO_BLK_F_DISCARD |
        1ull << VIRTIO_BLK_F_WRITE_ZEROES | 1ull << VIRTIO_F_VERSION_1 |
        1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_RING_F_EVENT_IDX |
        1ull << VHOST_USER_F_PROTOCOL_FEATURES |
        (readonly ? 1ull << VIRTIO_BLK_F_RO : 0)
    ),
    _protocol_features(0),
    _config{},
    _wce_enabled(write_cache_enabled),
    _postcopy_listening(false),
    _wake_fd(wake_fd),
    _inflight_fd(-1),
    _inflight_addr(nullptr),
    _inflight_size(0),
    _inflight_num_queues(0),
    _inflight_queue_size(0) {
    _regions.reserve(VHOST_USER_MAX_RAM_SLOTS);

    int res = rawio_queue_create(queue_size, &_queue);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    try {
        // rawstor_target_spec() (unlike rawstor_target_open()) fetches an
        // object's spec without opening it -- exactly what's needed here,
        // since nothing on Device itself does data-plane I/O against the
        // target: each VirtQueue opens its own RawstorObject (see _vq()).
        RawstorObjectSpec spec = spec_object(_queue, target);

        _config.capacity = spec.size >> VIRTIO_BLK_SECTOR_BITS;

        _config.size_max = 1 << 16; // VIRTIO_BLK_F_SIZE_MAX

        _config.seg_max = (1 << 7) - 2; // VIRTIO_BLK_F_SEG_MAX

        _config.geometry = {}; // VIRTIO_BLK_F_GEOMETRY

        _config.blk_size = 1 << VIRTIO_BLK_SECTOR_BITS; // VIRTIO_BLK_F_BLK_SIZE

        _config.physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
        _config.alignment_offset = 0;
        _config.min_io_size = 1;
        _config.opt_io_size = 1;

        _config.wce = write_cache_enabled; // VIRTIO_BLK_F_CONFIG_WCE

        // VIRTIO_BLK_F_MQ -- QEMU overrides this with its own
        // `num-queues=` before the guest ever reads it; see the class
        // comment.
        _config.num_queues = max_queues();

        // VIRTIO_BLK_F_DISCARD -- one segment per request (matches
        // discard_task()'s own per-segment dispatch loop,
        // virtqueue_worker.cpp, which handles more than one only
        // defensively); capped to UINT32_MAX sectors since the field
        // itself is 32 bits.
        _config.max_discard_sectors = static_cast<uint32_t>(
            std::min<uint64_t>(_config.capacity, UINT32_MAX)
        );
        _config.max_discard_seg = 1;
        _config.discard_sector_alignment =
            _config.blk_size >> VIRTIO_BLK_SECTOR_BITS;

        // VIRTIO_BLK_F_WRITE_ZEROES -- same one-segment-per-request shape
        // as discard above; write_zeroes_may_unmap advertises that this
        // device may deallocate storage for a range the guest flags
        // UNMAP (see write_zeroes_task()'s own use of the flag).
        _config.max_write_zeroes_sectors = static_cast<uint32_t>(
            std::min<uint64_t>(_config.capacity, UINT32_MAX)
        );
        _config.max_write_zeroes_seg = 1;
        _config.write_zeroes_may_unmap = 1;

        _config.max_secure_erase_sectors =
            0; // VIRTIO_BLK_F_SECURE_ERASE (unsupported)
        _config.max_secure_erase_seg = 0;
        _config.secure_erase_sector_alignment = 0;

        _config.zoned = {}; // VIRTIO_BLK_F_ZONED (unsupported)
    } catch (...) {
        // _wake_fd itself needs no cleanup here: wake_task() (which is
        // what would ever arm a read on it) is only ever launched from
        // loop(), never reached during construction, and Device doesn't
        // own the fd anyway -- see its own doc comment.
        rawio_queue_delete(_queue);
        throw;
    }
}

Device::~Device() {
    // Let every request already in flight complete (and its completion
    // reach the used ring) before going away: on reconnecting, QEMU
    // carries on from used->idx when GET_VRING_BASE went unanswered, so
    // whatever is left in flight here would never complete for the guest.
    // pause() rather than just stop(), since a VIRTIO_BLK_T_FLUSH still in
    // flight on one VirtQueue needs every other one still running to
    // complete -- see other_vqs().
    rawstd_info("Waiting for in-flight requests to complete\n");
    for (auto& vq : _vqs) {
        if (vq != nullptr) {
            vq->pause();
        }
    }

    // Each VirtQueue tears down its own kick_fd/call_fd ops, its own
    // RawstorObject and its own RawIOQueue on its own thread as part of
    // stop() -- see VirtQueue::_run().
    for (auto& vq : _vqs) {
        if (vq != nullptr) {
            vq->stop();
        }
    }

    // Only now that no VirtQueue can still be writing to it.
    if (_inflight_addr != nullptr) {
        munmap(_inflight_addr, _inflight_size);
    }
    if (_inflight_fd != -1) {
        close(_inflight_fd);
    }

    int cres = rawio_cancel_all(_queue, _fd);
    if (cres && cres != -ENOENT) {
        rawstd_error(
            "Failed to cancel pending control socket ops: %s\n", strerror(-cres)
        );
    }

    // Only cancels whatever wake_task() read may still be outstanding on
    // _wake_fd (needed before rawio_queue_delete() below regardless of
    // ownership) -- Device never owns this fd, so there is nothing to
    // close() here; see its own doc comment.
    if (_wake_fd != -1) {
        int wcres = rawio_cancel_all(_queue, _wake_fd);
        if (wcres && wcres != -ENOENT) {
            rawstd_error(
                "Failed to cancel pending wake fd ops: %s\n", strerror(-wcres)
            );
        }
    }

    rawio_queue_delete(_queue);

    if (_backend_fd != -1) {
        try {
            if (close(_backend_fd)) {
                RAWSTD_THROW_ERRNO();
            }
        } catch (std::exception& e) {
            std::ostringstream oss;
            oss << "Failed to close backend fd: " << e.what();
            rawstd_error("%s\n", oss.str().c_str());
        }
    }

    try {
        if (close(_fd)) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (std::exception& e) {
        std::ostringstream oss;
        oss << "Failed to close socket: " << e.what();
        rawstd_error("%s\n", oss.str().c_str());
    }
}

void Device::notify_reconnect_hint(int fd) {
    notify_eventfd(_queue, fd, 1);
}

void Device::set_features(uint64_t features) {
    if (!(features & (1ull << VIRTIO_F_VERSION_1))) {
        throw std::runtime_error("virtio legacy devices are not supported");
    }

    _features.store(features, std::memory_order_relaxed);

    // Without VHOST_USER_F_PROTOCOL_FEATURES a ring starts out enabled;
    // _vq() does the same for any VirtQueue created after this point.
    if (!(features & (1ull << VHOST_USER_F_PROTOCOL_FEATURES))) {
        for (auto& vq : _vqs) {
            if (vq != nullptr) {
                vq->post_set_enabled(true);
            }
        }
    }
}

uint64_t Device::get_protocol_features() const noexcept {
    return (1ull << VHOST_USER_PROTOCOL_F_MQ |
            1ull << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
            1ull << VHOST_USER_PROTOCOL_F_REPLY_ACK |
            1ull << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
            1ull << VHOST_USER_PROTOCOL_F_CONFIG |
            1ull << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD) |
           _protocol_features;
}

VirtQueue& Device::_vq(size_t index) {
    std::unique_ptr<VirtQueue>& slot = _vqs.at(index);
    if (slot != nullptr) {
        return *slot;
    }

    // Each VirtQueue opens its own RawstorObject (a fresh
    // rawstor_target_open() against the same target) and runs on its own
    // thread from here on -- see VirtQueue's class comment for why
    // sharing one RawstorObject across threads isn't an option. start()
    // blocks until it's actually up; if it throws, `vq` is back to its
    // not-started state and simply destroyed, the slot left empty.
    auto vq = std::make_unique<VirtQueue>();
    vq->attach(*this, index);
    vq->start(_target, _queue_size, _readonly);
    rawstd_info("Started virtqueue %zu\n", index);

    InflightRegion* region = _inflight_region(index);
    if (region != nullptr) {
        vq->post_set_inflight(region);
    }

    {
        std::unique_lock lock(_vqs_mutex);
        slot = std::move(vq);
    }

    if (!(get_features() & (1ull << VHOST_USER_F_PROTOCOL_FEATURES))) {
        slot->post_set_enabled(true);
    }

    return *slot;
}

void Device::set_vring_size(size_t index, unsigned int size) {
    _vq(index).post_set_vring_size(size);
}

void Device::set_vring_base(size_t index, unsigned int idx) {
    _vq(index).post_set_vring_base(idx);
}

void Device::set_vring_kick(size_t index, int fd) {
    _vq(index).post_set_kick_fd(fd);
}

void Device::set_vring_call(size_t index, int fd) {
    _vq(index).post_set_call_fd(fd);
}

void Device::set_vring_err(size_t index, int fd) {
    _vq(index).post_set_err_fd(fd);
}

void Device::set_vring_addr(const vhost_vring_addr& vra) {
    _vq(vra.index).post_set_vring_addr(vra);
}

void Device::set_vring_enable(size_t index, bool enabled) {
    _vq(index).post_set_enabled(enabled);
}

uint16_t Device::get_vring_base(size_t index) {
    return _vq(index).get_vring_base();
}

void* Device::userspace_va_to_va(uint64_t userspace_addr) const noexcept {
    std::shared_lock lock(_regions_mutex);

    // Find matching memory region.
    for (auto& r : _regions) {
        if ((userspace_addr >= r->userspace_address()) &&
            (userspace_addr < (r->userspace_address() + r->memory_size()))) {
            uint64_t offset = userspace_addr - r->userspace_address();
            return (char*)r->mmap_addr() + r->mmap_offset() + offset;
        }
    }

    return nullptr;
}

void* Device::guest_phys_to_va(uint64_t gpa) const noexcept {
    // _regions is kept sorted (and non-overlapping) by guest_phys_addr --
    // see find_mem_region_pos() -- so, unlike userspace_va_to_va() above,
    // the containing region can be found with a binary search instead of
    // a linear scan. This is the hot path (once per virtqueue descriptor,
    // now on whichever VirtQueue thread that descriptor belongs to), so
    // it matters -- the shared_lock below only ever contends with
    // add_mem_reg()/rem_mem_reg(), both rare control-plane events.
    std::shared_lock lock(_regions_mutex);

    size_t low = 0;
    size_t high = _regions.size();

    while (low < high) {
        size_t mid = low + (high - low) / 2;
        const DevRegion& r = *_regions[mid];

        if (gpa < r.guest_phys_addr()) {
            high = mid;
        } else if (gpa >= r.guest_phys_addr() + r.memory_size()) {
            low = mid + 1;
        } else {
            uint64_t offset = gpa - r.guest_phys_addr();
            return (char*)r.mmap_addr() + r.mmap_offset() + offset;
        }
    }

    return nullptr;
}

void Device::set_config(
    const uint8_t* data, uint32_t offset, uint32_t size, uint32_t flags
) {
    /* don't support live migration */
    if (flags != VHOST_SET_CONFIG_TYPE_FRONTEND) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (offset != offsetof(virtio_blk_config, wce)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (size != 1) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    _config.wce = *data;
    _wce_enabled.store(*data != 0, std::memory_order_relaxed);
}

InflightRegion* Device::_inflight_region(size_t index) const noexcept {
    if (_inflight_addr == nullptr || index >= _inflight_num_queues) {
        return nullptr;
    }
    return reinterpret_cast<InflightRegion*>(
        static_cast<char*>(_inflight_addr) +
        index * inflight_region_size(_inflight_queue_size)
    );
}

void Device::_map_inflight(
    int fd, uint64_t mmap_size, uint64_t mmap_offset, uint16_t num_queues,
    uint16_t queue_size
) {
    if (num_queues == 0 || queue_size == 0 ||
        mmap_size < num_queues * inflight_region_size(queue_size)) {
        close(fd);
        throw std::runtime_error("in-flight memory too small for its queues");
    }

    void* addr = mmap(
        nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
        static_cast<off_t>(mmap_offset)
    );
    if (addr == MAP_FAILED) {
        int errsv = errno;
        close(fd);
        RAWSTD_THROW_SYSTEM_ERROR(errsv);
    }

    // No VirtQueue may touch the old regions once they're unmapped below:
    // paused, none pops or completes anything, and the SetInflight posted
    // after each pause() is applied before its resume().
    for (auto& vq : _vqs) {
        if (vq != nullptr) {
            vq->pause();
        }
    }

    void* old_addr = _inflight_addr;
    size_t old_size = _inflight_size;
    int old_fd = _inflight_fd;

    _inflight_fd = fd;
    _inflight_addr = addr;
    _inflight_size = mmap_size;
    _inflight_num_queues = num_queues;
    _inflight_queue_size = queue_size;

    for (uint16_t i = 0; i < num_queues; ++i) {
        _inflight_region(i)->desc_num = queue_size;
    }

    for (size_t i = 0; i < _vqs.size(); ++i) {
        if (_vqs[i] != nullptr) {
            _vqs[i]->post_set_inflight(_inflight_region(i));
            _vqs[i]->resume();
        }
    }

    if (old_addr != nullptr) {
        munmap(old_addr, old_size);
    }
    if (old_fd != -1) {
        close(old_fd);
    }
}

int Device::get_inflight_fd(
    uint16_t num_queues, uint16_t queue_size, uint64_t& mmap_size
) {
    mmap_size = num_queues * inflight_region_size(queue_size);
    int fd = create_shm(mmap_size);
    _map_inflight(fd, mmap_size, 0, num_queues, queue_size);
    return fd;
}

void Device::set_inflight_fd(
    int fd, uint64_t mmap_size, uint64_t mmap_offset, uint16_t num_queues,
    uint16_t queue_size
) {
    _map_inflight(fd, mmap_size, mmap_offset, num_queues, queue_size);
}

uint64_t Device::add_mem_reg(const VhostUserMemoryRegion& m, int fd) {
    std::unique_lock lock(_regions_mutex);

    if (_regions.size() >= VHOST_USER_MAX_RAM_SLOTS) {
        throw std::runtime_error(
            "failing attempt to hot add memory region because the backend has "
            "no free ram slots available"
        );
    }

    size_t idx = find_mem_region_pos(_regions, m);

    std::unique_ptr<DevRegion> region =
        std::make_unique<DevRegion>(m, fd, _postcopy_listening);

    rawstd_debug("Adding region %zu\n", _regions.size());
    rawstd_debug(
        "    guest_phys_addr: 0x%llx\n", (unsigned long long)m.guest_phys_addr
    );
    rawstd_debug(
        "    memory_size:     0x%llx\n", (unsigned long long)m.memory_size
    );
    rawstd_debug(
        "    userspace_addr:  0x%llx\n", (unsigned long long)m.userspace_addr
    );

    uint64_t ret = m.userspace_addr;

    _regions.insert(_regions.begin() + idx, std::move(region));

    return ret;
}

void Device::rem_mem_reg(const VhostUserMemoryRegion& m) {
    // Pausing every VirtQueue first (and only resuming once the region
    // is actually gone) closes a use-after-unmap window that a lock
    // around _regions alone wouldn't: DevRegion::~DevRegion() munmap()s
    // immediately on erase() below, and a VirtQueue thread could
    // otherwise be handed a pointer into this region by guest_phys_to_va()
    // moments before that munmap() -- pause() guarantees no VirtQueue is
    // popping new descriptors (so can't start a fresh translation into
    // this region) and that every request it had already translated has
    // fully completed before we get here.
    for (auto& vq : _vqs) {
        if (vq != nullptr) {
            vq->pause();
        }
    }

    bool removed = false;
    {
        std::unique_lock lock(_regions_mutex);

        for (auto it = _regions.begin(); it != _regions.end(); ++it) {
            if ((*it)->guest_phys_addr() == m.guest_phys_addr &&
                (*it)->memory_size() == m.memory_size) {
                rawstd_debug(
                    "Removing region at gpa 0x%llx\n",
                    (unsigned long long)m.guest_phys_addr
                );
                _regions.erase(it);
                removed = true;
                break;
            }
        }
    }

    for (auto& vq : _vqs) {
        if (vq != nullptr) {
            vq->resume();
        }
    }

    if (!removed) {
        rawstd_warning(
            "VHOST_USER_REM_MEM_REG: no matching region for gpa 0x%llx\n",
            (unsigned long long)m.guest_phys_addr
        );
    }
}

std::vector<VirtQueue*> Device::other_vqs(VirtQueue& requester) {
    std::shared_lock lock(_vqs_mutex);
    std::vector<VirtQueue*> others;
    for (auto& vq : _vqs) {
        if (vq != nullptr && vq.get() != &requester) {
            others.push_back(vq.get());
        }
    }
    return others;
}

void Device::loop() {
    bool done = false;
    dispatch_loop(_queue, _fd, *this, done);
    if (_wake_fd != -1) {
        wake_task(_queue, _wake_fd, done);
    }
    rawstd::DetachedTask::rethrow_if_pending();

    while (!done) {
        int res = rawio_wait(_queue);
        if (res == -EINTR) {
            return;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace vhost
} // namespace rawstor
