#include "device.hpp"

#include "protocol.h"
#include "stdheaders/linux/virtio_blk.h"
#include "stdheaders/linux/virtio_config.h"
#include "stdheaders/linux/virtio_ring.h"

#include <rawstd/endian.h>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

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

class DeviceOp {
private:
    rawstor::vhost::Device& _client;
    VhostUserHeader _header;
    VhostUserPayload _payload;
    VhostUserFds _fds;

public:
    DeviceOp(rawstor::vhost::Device& client) : _client(client) {}
    DeviceOp(const DeviceOp&) = delete;
    DeviceOp(DeviceOp&&) = delete;
    DeviceOp& operator=(const DeviceOp&) = delete;
    DeviceOp& operator=(DeviceOp&&) = delete;

    inline rawstor::vhost::Device& device() noexcept { return _client; }

    inline VhostUserHeader& header() noexcept { return _header; }

    inline VhostUserPayload& payload() noexcept { return _payload; }

    inline VhostUserFds& fds() noexcept { return _fds; }
};

class Task {
protected:
    std::shared_ptr<DeviceOp> _op;

public:
    static int callback(size_t result, int error, void* data) {
        std::unique_ptr<Task> t(static_cast<Task*>(data));
        try {
            (*t)(result, error);
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            return -EINVAL;
        }
    }

    Task(const std::shared_ptr<DeviceOp>& op) : _op(op) {}
    Task(const Task&) = delete;
    Task(Task&&) = delete;
    virtual ~Task() {}

    Task& operator=(const Task&) = delete;
    Task& operator=(Task&&) = delete;

    virtual void operator()(size_t result, int error) = 0;
};

class TaskScalar : public Task {
public:
    TaskScalar(const std::shared_ptr<DeviceOp>& op) : Task(op) {}

    virtual void* buf() noexcept = 0;
    virtual size_t size() const noexcept = 0;
};

class TaskMessage : public Task {
public:
    TaskMessage(const std::shared_ptr<DeviceOp>& op) : Task(op) {}

    virtual msghdr* msg() noexcept = 0;
    virtual size_t size() const noexcept = 0;
    virtual int flags() const noexcept = 0;
};

void read(RawIOQueue* queue, int fd, std::unique_ptr<TaskScalar> t) {
    int res = rawio_read(queue, fd, t->buf(), t->size(), t->callback, t.get());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

void read(RawIOQueue* queue, int fd, std::unique_ptr<TaskMessage> t) {
    int res =
        rawio_recvmsg(queue, fd, t->msg(), t->flags(), t->callback, t.get());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

void write(RawIOQueue* queue, int fd, std::unique_ptr<TaskScalar> t) {
    int res = rawio_write(queue, fd, t->buf(), t->size(), t->callback, t.get());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

void write(RawIOQueue* queue, int fd, std::unique_ptr<TaskMessage> t) {
    int res =
        rawio_sendmsg(queue, fd, t->msg(), t->flags(), t->callback, t.get());
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}

class TaskEventFd final : public TaskScalar {
private:
    uint64_t _value;

public:
    TaskEventFd(const std::shared_ptr<DeviceOp>& op, uint64_t value) :
        TaskScalar(op),
        _value(value) {}

    void* buf() noexcept { return &_value; }

    size_t size() const noexcept { return sizeof(_value); }

    void operator()(size_t result, int error) {
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }

        if (result != sizeof(uint64_t)) {
            rawstd_error("Unexpected eventfd size: %zu\n", result);
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
    }
};

class TaskWriteMsg : public TaskMessage {
private:
    iovec _iov[2];
    char _control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))];
    msghdr _msg;

public:
    TaskWriteMsg(
        const std::shared_ptr<DeviceOp>& op, size_t payload_size,
        uint32_t flags, int nfds
    ) :
        TaskMessage(op),
        _iov{
            {
                .iov_base = &op->header(),
                .iov_len = sizeof(op->header()),
            },
            {
                .iov_base = &op->payload(),
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

        VhostUserHeader& header = _op->header();

        header.flags = flags;
        header.flags &= ~VHOST_USER_VERSION_MASK;
        header.flags |= VHOST_USER_VERSION;
        header.flags |= VHOST_USER_REPLY_MASK;

        header.size = payload_size;

        const VhostUserFds& fds = _op->fds();
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

    void operator()(size_t result, int error) override {
        if (error != 0) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }

        if (result != size()) {
            rawstd_error("Unexpected response size: %zu\n", result);
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_debug("Message sent: %zu bytes\n", result);
    }

    inline msghdr* msg() noexcept override { return &_msg; }

    size_t size() const noexcept override {
        return _iov[0].iov_len + _iov[1].iov_len;
    }

    inline int flags() const noexcept override { return 0; }

    virtual std::string str() const = 0;
};

class TaskWriteEmpty : public TaskWriteMsg {
public:
    TaskWriteEmpty(const std::shared_ptr<DeviceOp>& op) :
        TaskWriteMsg(op, 0, 0, 0) {}

    std::string str() const override { return "empty"; }
};

class TaskWriteU64 : public TaskWriteMsg {
public:
    TaskWriteU64(const std::shared_ptr<DeviceOp>& op, uint64_t value) :
        TaskWriteMsg(op, sizeof(op->payload().u64), 0, 0) {
        VhostUserPayload& payload = _op->payload();

        payload.u64 = value;
    }

    std::string str() const override {
        std::ostringstream oss;
        oss << "u64: 0x" << std::hex << _op->payload().u64;
        return oss.str();
    }
};

class TaskWriteState : public TaskWriteMsg {
public:
    TaskWriteState(
        const std::shared_ptr<DeviceOp>& op, const vhost_vring_state& state
    ) :
        TaskWriteMsg(op, sizeof(op->payload().state), 0, 0) {
        VhostUserPayload& payload = _op->payload();

        payload.state = state;
    }

    std::string str() const override {
        std::ostringstream oss;
        const vhost_vring_state& state = _op->payload().state;
        oss << "state(index=" << state.index << ", num=" << state.num << ")";
        return oss.str();
    }
};

class TaskWriteConfig : public TaskWriteMsg {
public:
    TaskWriteConfig(
        const std::shared_ptr<DeviceOp>& op, const virtio_blk_config& config
    ) :
        TaskWriteMsg(op, op->header().size, 0, 0) {
        VhostUserPayload& payload = _op->payload();
        assert(payload.config.size <= sizeof(virtio_blk_config));

        memcpy(payload.config.region, &config, payload.config.size);
    }

    std::string str() const override {
        std::ostringstream oss;
        VhostUserPayload& payload = _op->payload();

        oss << "config(" << payload.config.size << ")";
        return oss.str();
    }
};

class TaskWriteMemRegMsg : public TaskWriteMsg {
public:
    TaskWriteMemRegMsg(
        const std::shared_ptr<DeviceOp>& op, const VhostUserMemRegMsg& msg
    ) :
        TaskWriteMsg(op, sizeof(TaskWriteMemRegMsg), 0, 0) {
        VhostUserPayload& payload = _op->payload();

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
std::unique_ptr<TaskWriteMsg>
get_features(const std::shared_ptr<DeviceOp>& op) {
    return std::make_unique<TaskWriteU64>(op, op->device().get_features());
}

/**
 * Enable features in the underlying vhost implementation using a bitmask.
 * Feature bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
 * VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
 */
std::unique_ptr<TaskWriteMsg>
set_features(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();

    op->device().set_features(payload.u64);

    return nullptr;
}

/**
 * Issued when a new connection is established. It marks the sender as the
 * front-end that owns of the session. This can be used on the back-end as a
 * "session start" flag.
 */
std::unique_ptr<TaskWriteMsg> set_owner(const std::shared_ptr<DeviceOp>&) {
    return nullptr;
}

/**
 * Set the size of the queue.
 */
std::unique_ptr<TaskWriteMsg>
set_vring_num(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();

    unsigned int index = payload.state.index;
    unsigned int num = payload.state.num;

    rawstd_debug("State.index: %u\n", index);
    rawstd_debug("State.num:   %u\n", num);

    op->device().set_vring_size(index, num);

    return nullptr;
}

/**
 * Sets the addresses of the different aspects of the vring.
 */
std::unique_ptr<TaskWriteMsg>
set_vring_addr(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();
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

    op->device().set_vring_addr(vra);

    return nullptr;
}

/**
 * Sets the next index to use for descriptors in this vring.
 */
std::unique_ptr<TaskWriteMsg>
set_vring_base(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();

    unsigned int index = payload.state.index;
    unsigned int num = payload.state.num;

    rawstd_debug("State.index: %u\n", index);
    rawstd_debug("State.num:   %u\n", num);

    op->device().set_vring_base(index, num);

    return nullptr;
}

/**
 * Set the event file descriptor for adding buffers to the vring. It is passed
 * in the ancillary data.
 */
std::unique_ptr<TaskWriteMsg>
set_vring_kick(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserHeader& header = op->header();
    const VhostUserPayload& payload = op->payload();
    VhostUserFds& fds = op->fds();

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
        op->device().set_vring_kick(index, fd);
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
std::unique_ptr<TaskWriteMsg>
set_vring_call(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserHeader& header = op->header();
    const VhostUserPayload& payload = op->payload();
    VhostUserFds& fds = op->fds();

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
        op->device().set_vring_call(index, fd);
    } catch (...) {
        if (fd != -1) {
            close(fd);
        }
        throw;
    }

    // in case of I/O hang after reconnecting
    if (fd != -1) {
        std::unique_ptr<TaskEventFd> t = std::make_unique<TaskEventFd>(op, 1);
        write(op->device().queue(), fd, std::move(t));
    }

    return nullptr;
}

/**
 * Set the event file descriptor to signal when error occurs. It is passed in
 * the ancillary data.
 */
std::unique_ptr<TaskWriteMsg>
set_vring_err(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserHeader& header = op->header();
    const VhostUserPayload& payload = op->payload();
    VhostUserFds& fds = op->fds();

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
        op->device().set_vring_err(index, fd);
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
std::unique_ptr<TaskWriteMsg>
set_vring_enable(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();

    unsigned int index = payload.state.index;
    bool enable = payload.state.num != 0;

    rawstd_debug("State.index:  %u\n", index);
    rawstd_debug("State.enable: %u\n", enable);

    op->device().set_vring_enable(index, enable);

    return nullptr;
}

/**
 * Front-end requests the current vring base index, used before tearing down
 * or migrating a ring. The back-end must stop processing the ring and reply
 * with the index up to which it has consumed the avail ring.
 */
std::unique_ptr<TaskWriteMsg>
get_vring_base(const std::shared_ptr<DeviceOp>& op) {
    VhostUserPayload& payload = op->payload();

    unsigned int index = payload.state.index;

    vhost_vring_state state;
    state.index = index;
    state.num = op->device().get_vring_base(index);

    return std::make_unique<TaskWriteState>(op, state);
}

/**
 * Get the protocol feature bitmask from the underlying vhost implementation.
 */
std::unique_ptr<TaskWriteMsg>
get_protocol_features(const std::shared_ptr<DeviceOp>& op) {
    return std::make_unique<TaskWriteU64>(
        op, op->device().get_protocol_features()
    );
}

/**
 * Enable protocol features in the underlying vhost implementation using a
 * bitmask.
 */
std::unique_ptr<TaskWriteMsg>
set_protocol_features(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();

    rawstd_debug(
        "Setting features u64: 0x%llx\n", (unsigned long long)payload.u64
    );

    op->device().set_protocol_features(payload.u64);

    return nullptr;
}

/**
 * Query how many queues the back-end supports.
 */
std::unique_ptr<TaskWriteMsg>
get_queue_num(const std::shared_ptr<DeviceOp>& op) {
    return std::make_unique<TaskWriteU64>(op, op->device().nqueues());
}

/**
 * Set the socket file descriptor for back-end initiated requests. It is
 * passed in the ancillary data.
 */
std::unique_ptr<TaskWriteMsg>
set_backend_req_fd(const std::shared_ptr<DeviceOp>& op) {
    VhostUserFds& fds = op->fds();

    if (fds.fd_num != 1) {
        rawstd_error("Invalid backend_req_fd message (%d fd's)", fds.fd_num);
        close_fds(fds);
        return nullptr;
    }

    rawstd_debug("Got backend_fd: %d\n", fds.fds[0]);
    op->device().set_backend_fd(fds.fds[0]);

    return nullptr;
}

/**
 * When VHOST_USER_PROTOCOL_F_CONFIG is negotiated, this message is submitted
 * by the vhost-user front-end to fetch the contents of the virtio device
 * configuration space.
 */
std::unique_ptr<TaskWriteMsg> get_config(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserPayload& payload = op->payload();
    if (payload.config.size > sizeof(virtio_blk_config)) {
        /**
         * Return zero to indicate an error to frontend
         */
        return std::make_unique<TaskWriteEmpty>(op);
    }

    return std::make_unique<TaskWriteConfig>(op, op->device().get_config());
}

/**
 * The front-end updates a portion of the virtio device configuration space.
 */
std::unique_ptr<TaskWriteMsg> set_config(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserHeader& header = op->header();
    const VhostUserPayload& payload = op->payload();
    const VhostUserConfig& c = payload.config;

    bool need_reply = header.flags & VHOST_USER_NEED_REPLY_MASK;

    try {
        op->device().set_config(c.region, c.offset, c.size, c.flags);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return need_reply ? std::make_unique<TaskWriteU64>(op, 1) : nullptr;
    }

    return need_reply ? std::make_unique<TaskWriteU64>(op, 0) : nullptr;
}

/**
 * When the VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS protocol feature has
 * been successfully negotiated, this message is submitted by the front-end
 * to the back-end to learn the maximum number of memory slots it may expose
 * to the guest.
 */
std::unique_ptr<TaskWriteMsg>
get_max_mem_slots(const std::shared_ptr<DeviceOp>& op) {
    return std::make_unique<TaskWriteU64>(op, op->device().get_max_mem_slots());
}

/**
 * Registers a new guest memory region with the back-end. Exactly one file
 * descriptor from which the memory is mapped is passed in the ancillary
 * data.
 */
std::unique_ptr<TaskWriteMsg> add_mem_reg(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserHeader& header = op->header();
    VhostUserPayload& payload = op->payload();
    VhostUserFds& fds = op->fds();

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

    if (op->device().nregions() == VHOST_USER_MAX_RAM_SLOTS) {
        rawstd_error(
            "failing attempt to hot add memory via "
            "VHOST_USER_ADD_MEM_REG message because the backend has "
            "no free ram slots available"
        );
        close_fds(fds);
        return nullptr;
    }

    m.region.userspace_addr = op->device().add_mem_reg(m.region, fds.fds[0]);

    close(fds.fds[0]);

    rawstd_debug("Successfully added new region\n");

    return nullptr;
}

/**
 * Removes a guest memory region previously registered via
 * VHOST_USER_ADD_MEM_REG. Identified by guest physical address and size; the
 * file descriptor, if any is attached, is not used.
 */
std::unique_ptr<TaskWriteMsg> rem_mem_reg(const std::shared_ptr<DeviceOp>& op) {
    const VhostUserHeader& header = op->header();
    VhostUserPayload& payload = op->payload();
    VhostUserFds& fds = op->fds();

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

    op->device().rem_mem_reg(payload.memreg.region);

    return nullptr;
}

/**
 * Reset feature negotiation; sent rarely by modern front-ends. We simply
 * acknowledge it.
 */
std::unique_ptr<TaskWriteMsg> reset_owner(const std::shared_ptr<DeviceOp>&) {
    return nullptr;
}

std::unique_ptr<TaskWriteMsg> response(const std::shared_ptr<DeviceOp>& op) {
    switch (op->header().request) {
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
    default:
        rawstd_error("Unexpected request: %d\n", op->header().request);
        throw std::runtime_error("Unexpected request");
    };
}

void dispatch(const std::shared_ptr<DeviceOp>& op) {
    VhostUserHeader& header = op->header();

    rawstd_debug("============= Vhost user message =============\n");
    rawstd_debug("Request: %d\n", header.request);
    rawstd_debug("Flags:   0x%x\n", header.flags);
    rawstd_debug("Size:    %u\n", header.size);

#if RAWSTD_LOGLEVEL >= RAWSTD_LOGLEVEL_DEBUG
    VhostUserFds& fds = op->fds();
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

    std::unique_ptr<TaskWriteMsg> t = response(op);
    if (t.get() == nullptr && need_reply) {
        t = std::make_unique<TaskWriteU64>(op, 0);
    }
    if (t.get() != nullptr) {
        rawstd_debug("Sending back to guest: %s\n", t->str().c_str());
        write(op->device().queue(), op->device().fd(), std::move(t));
    }
}

class TaskReadUserHeader final : public TaskMessage {
private:
    iovec _iov;
    char _control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))];
    msghdr _msg;

public:
    TaskReadUserHeader(const std::shared_ptr<DeviceOp>& op) :
        TaskMessage(op),
        _iov{.iov_base = &_op->header(), .iov_len = sizeof(_op->header())},
        _msg{
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &_iov,
            .msg_iovlen = 1,
            .msg_control = &_control,
            .msg_controllen = sizeof(_control),
            .msg_flags = 0,
        } {}

    inline msghdr* msg() noexcept override { return &_msg; }

    size_t size() const noexcept override { return sizeof(_op->header()); }

    inline int flags() const noexcept override { return MSG_WAITALL; }

    void operator()(size_t result, int error) override;
};

class TaskReadUserPayload final : public TaskScalar {
private:
    size_t _payload_size;

public:
    TaskReadUserPayload(
        const std::shared_ptr<DeviceOp>& op, size_t payload_size
    ) :
        TaskScalar(op),
        _payload_size(payload_size) {}

    inline void* buf() noexcept override { return &_op->payload(); }

    size_t size() const noexcept override { return _payload_size; }

    void operator()(size_t result, int error) override;
};

void TaskReadUserHeader::operator()(size_t result, int error) {
    if (error != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    if (result == 0) {
        // Front-end closed the connection at a message boundary: a normal
        // disconnect, not a malformed request. Treat it like EPIPE so
        // Device::loop() exits cleanly instead of reporting it as a
        // protocol error.
        RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
    }

    if (result != size()) {
        rawstd_error("Unexpected request header size: %zu\n", result);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    VhostUserFds& fds = _op->fds();
    fds.fd_num = 0;
    cmsghdr* cmsg;
    for (cmsg = CMSG_FIRSTHDR(&_msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&_msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t fd_size = cmsg->cmsg_len - CMSG_LEN(0);
            fds.fd_num = fd_size / sizeof(int);
            assert(fds.fd_num <= VHOST_MEMORY_BASELINE_NREGIONS);
            memcpy(fds.fds, CMSG_DATA(cmsg), fd_size);
            break;
        }
    }

    const VhostUserHeader& header = _op->header();
    if (header.size != 0) {
        if (header.size > sizeof(VhostUserPayload)) {
            rawstd_error(
                "Unexpected request payload size: %u\n",
                (unsigned int)header.size
            );
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        std::unique_ptr<TaskReadUserPayload> t =
            std::make_unique<TaskReadUserPayload>(_op, header.size);
        read(_op->device().queue(), _op->device().fd(), std::move(t));
        return;
    }

    dispatch(_op);

    if (header.request == VHOST_USER_NONE) {
        return;
    }

    std::shared_ptr<DeviceOp> op = std::make_shared<DeviceOp>(_op->device());
    std::unique_ptr<TaskReadUserHeader> t =
        std::make_unique<TaskReadUserHeader>(op);
    read(op->device().queue(), op->device().fd(), std::move(t));
}

void TaskReadUserPayload::operator()(size_t result, int error) {
    if (error != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    if (result != size()) {
        rawstd_error("Unexpected request payload size: %zu\n", result);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    dispatch(_op);

    std::shared_ptr<DeviceOp> op = std::make_shared<DeviceOp>(_op->device());
    std::unique_ptr<TaskReadUserHeader> t =
        std::make_unique<TaskReadUserHeader>(op);
    read(op->device().queue(), op->device().fd(), std::move(t));
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

//
// virtio-blk data plane: turns descriptor chains popped off a virtqueue into
// asynchronous rawstor object I/O.
//

struct virtio_blk_inhdr {
    unsigned char status;
};

class Request final {
private:
    rawstor::vhost::Device& _device;
    size_t _index;
    std::unique_ptr<rawstor::vhost::DescChain> _chain;
    virtio_blk_inhdr* _in;
    iovec* _in_iov;
    unsigned int _in_niov;
    virtio_blk_outhdr _out;
    iovec* _out_iov;
    unsigned int _out_niov;

public:
    Request(
        rawstor::vhost::Device& device, size_t index,
        std::unique_ptr<rawstor::vhost::DescChain> chain
    ) :
        _device(device),
        _index(index),
        _chain(std::move(chain)),
        _in_iov(_chain->writable.data()),
        _in_niov(_chain->writable.size()),
        _out_iov(_chain->readable.data()),
        _out_niov(_chain->readable.size()) {
        if (_out_niov == 0 ||
            rawstd_iovec_to_buf(_out_iov, _out_niov, 0, &_out, sizeof(_out)) !=
                sizeof(_out)) {
            rawstd_error("virtio-blk request outhdr too short\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        rawstd_iovec_discard_front(&_out_iov, &_out_niov, sizeof(_out));

        if (_in_niov == 0 ||
            _in_iov[_in_niov - 1].iov_len < sizeof(virtio_blk_inhdr)) {
            rawstd_error("virtio-blk request inhdr too short\n");
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

        _in = reinterpret_cast<virtio_blk_inhdr*>(
            static_cast<char*>(_in_iov[_in_niov - 1].iov_base) +
            _in_iov[_in_niov - 1].iov_len - sizeof(virtio_blk_inhdr)
        );

        rawstd_iovec_discard_back(
            &_in_iov, &_in_niov, sizeof(virtio_blk_inhdr)
        );
    }

    inline rawstor::vhost::Device& device() noexcept { return _device; }

    inline iovec* in_iov() noexcept { return _in_iov; }

    inline unsigned int in_niov() noexcept { return _in_niov; }

    inline iovec* out_iov() noexcept { return _out_iov; }

    inline unsigned int out_niov() noexcept { return _out_niov; }

    inline uint32_t type() noexcept {
        return RAWSTD_LE32TOH(_out.type) & ~(uint32_t)VIRTIO_BLK_T_BARRIER;
    }

    inline uint64_t offset() noexcept {
        return RAWSTD_LE64TOH(_out.sector) << VIRTIO_BLK_SECTOR_BITS;
    }

    void push(unsigned char status, size_t size) {
        _in->status = status;
        _device.complete_request(
            _index, _chain->head,
            static_cast<uint32_t>(size + sizeof(virtio_blk_inhdr))
        );
    }
};

class ObjectTask final {
protected:
    std::unique_ptr<Request> _req;

public:
    static int callback(
        RawstorObject*, size_t size, size_t result, int error, void* data
    ) {
        std::unique_ptr<ObjectTask> t(static_cast<ObjectTask*>(data));
        try {
            (*t)(size, result, error);
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            return -EINVAL;
        }
    }

    ObjectTask(std::unique_ptr<Request> req) : _req(std::move(req)) {}
    ObjectTask(const ObjectTask&) = delete;
    ObjectTask(ObjectTask&&) = delete;
    ~ObjectTask() = default;

    ObjectTask& operator=(const ObjectTask&) = delete;
    ObjectTask& operator=(ObjectTask&&) = delete;

    void preadv();
    void pwritev();
    inline Request* req() noexcept { return _req.get(); }

    void operator()(size_t size, size_t result, int error);
};

void ObjectTask::operator()(size_t size, size_t result, int error) {
    if (error != 0) {
        rawstd_error("%s\n", strerror(error));
        _req->push(VIRTIO_BLK_S_IOERR, result);
        return;
    }

    if (result != size) {
        rawstd_error("Partial object operation: %zu != %zu\n", result, size);
        _req->push(VIRTIO_BLK_S_IOERR, result);
        return;
    }

    rawstd_debug("vhost: object operation completed, %zu bytes\n", result);
    _req->push(VIRTIO_BLK_S_OK, result);
}

void ObjectTask::preadv() {
    int res = rawstor_object_preadv(
        _req->device().object(), _req->in_iov(), _req->in_niov(),
        rawstd_iovec_size(_req->in_iov(), _req->in_niov()), _req->offset(),
        callback, this
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void ObjectTask::pwritev() {
    int res = rawstor_object_pwritev(
        _req->device().object(), _req->out_iov(), _req->out_niov(),
        rawstd_iovec_size(_req->out_iov(), _req->out_niov()), _req->offset(),
        callback, this
    );
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void process_request(std::unique_ptr<Request> req) {
    size_t in_size = rawstd_iovec_size(req->in_iov(), req->in_niov());
    size_t out_size = rawstd_iovec_size(req->out_iov(), req->out_niov());

    rawstd_debug(
        "vhost: request type %u offset %llu in_size %zu out_size %zu\n",
        req->type(), (unsigned long long)req->offset(), in_size, out_size
    );

    switch (req->type()) {
    case VIRTIO_BLK_T_IN: {
        std::unique_ptr<ObjectTask> t =
            std::make_unique<ObjectTask>(std::move(req));
        try {
            t->preadv();
            t.release();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            t->req()->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_OUT: {
        std::unique_ptr<ObjectTask> t =
            std::make_unique<ObjectTask>(std::move(req));
        try {
            t->pwritev();
            t.release();
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            t->req()->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_GET_ID: {
        try {
            char uuid[37];
            int res =
                rawstor_object_id(req->device().object(), uuid, sizeof(uuid));
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }

            size_t size = std::min(in_size, (size_t)VIRTIO_BLK_ID_BYTES);

            char* at = uuid;
            if (size < sizeof(uuid)) {
                at += sizeof(uuid) - size;
            } else {
                size = sizeof(uuid);
            }

            rawstd_iovec_from_buf(req->in_iov(), req->in_niov(), 0, at, size);

            req->push(VIRTIO_BLK_S_OK, in_size);
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
            req->push(VIRTIO_BLK_S_IOERR, in_size);
        }
        break;
    }

    case VIRTIO_BLK_T_FLUSH:
    case VIRTIO_BLK_T_DISCARD:
    case VIRTIO_BLK_T_WRITE_ZEROES:
    default:
        req->push(VIRTIO_BLK_S_UNSUPP, in_size);
        break;
    }
}

} // namespace

namespace rawstor {
namespace vhost {

Device::Device(unsigned int queue_size, const std::string& target, int fd) :
    _fd(fd),
    _queue(nullptr),
    _object(nullptr),
    _vqs(1),
    _backend_fd(-1),
    _features(
        1ull << VIRTIO_BLK_F_SIZE_MAX | 1ull << VIRTIO_BLK_F_SEG_MAX |
        1ull << VIRTIO_BLK_F_BLK_SIZE | 1ull << VIRTIO_BLK_F_TOPOLOGY |
        1ull << VIRTIO_BLK_F_MQ | 1ull << VIRTIO_F_VERSION_1 |
        1ull << VIRTIO_RING_F_INDIRECT_DESC | 1ull << VIRTIO_RING_F_EVENT_IDX |
        1ull << VHOST_USER_F_PROTOCOL_FEATURES
    ),
    _protocol_features(0),
    _config{},
    _postcopy_listening(false) {
    _regions.reserve(VHOST_USER_MAX_RAM_SLOTS);

    int res = rawio_queue_create(queue_size, &_queue);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    try {
        RawstorObjectSpec spec;
        res = rawstor_object_spec(target.c_str(), &spec);
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        res = rawstor_object_open(_queue, target.c_str(), &_object);
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        _config.capacity = spec.size >> VIRTIO_BLK_SECTOR_BITS;

        _config.size_max = 1 << 16; // VIRTIO_BLK_F_SIZE_MAX

        _config.seg_max = (1 << 7) - 2; // VIRTIO_BLK_F_SEG_MAX

        _config.geometry = {}; // VIRTIO_BLK_F_GEOMETRY

        _config.blk_size = 1 << VIRTIO_BLK_SECTOR_BITS; // VIRTIO_BLK_F_BLK_SIZE

        _config.physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
        _config.alignment_offset = 0;
        _config.min_io_size = 1;
        _config.opt_io_size = 1;

        _config.wce = 0; // VIRTIO_BLK_F_CONFIG_WCE

        _config.num_queues = nqueues(); // VIRTIO_BLK_F_MQ

        _config.max_discard_sectors = 0; // VIRTIO_BLK_F_DISCARD (unsupported)
        _config.max_discard_seg = 0;
        _config.discard_sector_alignment =
            _config.blk_size >> VIRTIO_BLK_SECTOR_BITS;

        _config.max_write_zeroes_sectors =
            0; // VIRTIO_BLK_F_WRITE_ZEROES (unsupported)
        _config.max_write_zeroes_seg = 0;
        _config.write_zeroes_may_unmap = 0;

        _config.max_secure_erase_sectors =
            0; // VIRTIO_BLK_F_SECURE_ERASE (unsupported)
        _config.max_secure_erase_seg = 0;
        _config.secure_erase_sector_alignment = 0;

        _config.zoned = {}; // VIRTIO_BLK_F_ZONED (unsupported)
    } catch (...) {
        if (_object != nullptr) {
            rawstor_object_close(_object);
        }
        rawio_queue_delete(_queue);
        throw;
    }
}

Device::~Device() {
    for (auto& vq : _vqs) {
        if (vq.kick_fd() != -1) {
            int res = rawio_cancel_all(_queue, vq.kick_fd());
            if (res && res != -ENOENT) {
                rawstd_error(
                    "Failed to cancel pending kick_fd ops: %s\n", strerror(-res)
                );
            }
        }
        if (vq.call_fd() != -1) {
            int res = rawio_cancel_all(_queue, vq.call_fd());
            if (res && res != -ENOENT) {
                rawstd_error(
                    "Failed to cancel pending call_fd ops: %s\n", strerror(-res)
                );
            }
        }
    }

    int cres = rawio_cancel_all(_queue, _fd);
    if (cres && cres != -ENOENT) {
        rawstd_error(
            "Failed to cancel pending control socket ops: %s\n", strerror(-cres)
        );
    }

    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            rawstd_error("Failed to close object: %s\n", strerror(-res));
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

void Device::set_features(uint64_t features) {
    if (!(features & (1ull << VIRTIO_F_VERSION_1))) {
        throw std::runtime_error("virtio legacy devices are not supported");
    }

    _features = features;

    if (!(_features & (1ull << VHOST_USER_F_PROTOCOL_FEATURES))) {
        for (size_t i = 0; i < _vqs.size(); ++i) {
            _vqs[i].set_enabled(*this, i, true);
        }
    }
}

uint64_t Device::get_protocol_features() const noexcept {
    return (1ull << VHOST_USER_PROTOCOL_F_MQ |
            1ull << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
            1ull << VHOST_USER_PROTOCOL_F_REPLY_ACK |
            1ull << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
            1ull << VHOST_USER_PROTOCOL_F_CONFIG) |
           _protocol_features;
}

void Device::set_vring_size(size_t index, unsigned int size) {
    _vqs.at(index).set_vring_size(size);
}

void Device::set_vring_base(size_t index, unsigned int idx) {
    _vqs.at(index).set_vring_base(idx);
}

void Device::set_vring_kick(size_t index, int fd) {
    _vqs.at(index).set_kick_fd(*this, index, fd);
}

void Device::set_vring_call(size_t index, int fd) {
    _vqs.at(index).set_call_fd(fd);
}

void Device::set_vring_err(size_t index, int fd) {
    _vqs.at(index).set_err_fd(fd);
}

void Device::set_vring_addr(const vhost_vring_addr& vra) {
    _vqs.at(vra.index).set_vring_addr(*this, vra);
}

void Device::set_vring_enable(size_t index, bool enabled) {
    _vqs.at(index).set_enabled(*this, index, enabled);
}

uint16_t Device::get_vring_base(size_t index) {
    VirtQueue& vq = _vqs.at(index);
    vq.set_enabled(*this, index, false);
    return vq.last_avail_idx();
}

void* Device::userspace_va_to_va(uint64_t userspace_addr) const noexcept {
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
    // Find matching memory region.
    for (auto& r : _regions) {
        if ((gpa >= r->guest_phys_addr()) &&
            (gpa < (r->guest_phys_addr() + r->memory_size()))) {
            uint64_t offset = gpa - r->guest_phys_addr();
            return (char*)r->mmap_addr() + r->mmap_offset() + offset;
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
}

uint64_t Device::add_mem_reg(const VhostUserMemoryRegion& m, int fd) {
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
    for (auto it = _regions.begin(); it != _regions.end(); ++it) {
        if ((*it)->guest_phys_addr() == m.guest_phys_addr &&
            (*it)->memory_size() == m.memory_size) {
            rawstd_debug(
                "Removing region at gpa 0x%llx\n",
                (unsigned long long)m.guest_phys_addr
            );
            _regions.erase(it);
            return;
        }
    }

    rawstd_warning(
        "VHOST_USER_REM_MEM_REG: no matching region for gpa 0x%llx\n",
        (unsigned long long)m.guest_phys_addr
    );
}

void Device::process_queue(size_t index) {
    VirtQueue& vq = _vqs.at(index);

    unsigned int npopped = 0;
    while (true) {
        std::unique_ptr<DescChain> chain = vq.pop(*this);
        if (chain == nullptr) {
            break;
        }
        ++npopped;

        try {
            std::unique_ptr<Request> req =
                std::make_unique<Request>(*this, index, std::move(chain));
            process_request(std::move(req));
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
        }
    }

    rawstd_debug("vhost: process_queue(%zu): popped %u chain(s)\n", index,
                 npopped);
}

void Device::complete_request(size_t index, uint16_t head, uint32_t len) {
    rawstd_debug(
        "vhost: complete_request(%zu): head %u len %u\n", index, head, len
    );
    VirtQueue& vq = _vqs.at(index);
    vq.push(head, len);
    vq.notify(*this, event_idx_negotiated());
}

void Device::loop() {
    std::shared_ptr<DeviceOp> op = std::make_shared<DeviceOp>(*this);
    std::unique_ptr<TaskReadUserHeader> t =
        std::make_unique<TaskReadUserHeader>(op);
    read(_queue, _fd, std::move(t));

    while (true) {
        int res = rawio_wait(_queue);
        if (res == -EPIPE || res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace vhost
} // namespace rawstor
