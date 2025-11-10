#include "device.hpp"

#include "protocol.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>


/* The version of the protocol we support */
#define VHOST_USER_VERSION 1

namespace {


class DeviceOp {
    private:
        rawstor::vhost::Device &_client;
        VhostUserHeader _header;
        VhostUserPayload _payload;
        VhostUserFds _fds;

    public:
        DeviceOp(rawstor::vhost::Device &client):
            _client(client)
        {}
        DeviceOp(const DeviceOp &) = delete;
        DeviceOp(DeviceOp &&) = delete;
        DeviceOp& operator=(const DeviceOp &) = delete;
        DeviceOp& operator=(DeviceOp &&) = delete;

        inline rawstor::vhost::Device& device() noexcept {
            return _client;
        }

        inline VhostUserHeader& header() noexcept {
            return _header;
        }

        inline VhostUserPayload& payload() noexcept {
            return _payload;
        }

        inline VhostUserFds& fds() noexcept {
            return _fds;
        }
};


class Task {
    protected:
        std::shared_ptr<DeviceOp> _op;

    public:
        static int callback(size_t result, int error, void *data) {
            std::unique_ptr<Task> t(static_cast<Task*>(data));
            try {
                (*t)(result, error);
                return 0;
            } catch (std::system_error &e) {
                return -e.code().value();
            }
        }

        Task(const std::shared_ptr<DeviceOp> &op):
            _op(op)
        {}
        Task(const Task &) = delete;
        Task(Task &&) = delete;
        virtual ~Task() {}

        Task& operator=(const Task &) = delete;
        Task& operator=(Task &&) = delete;

        virtual void operator()(size_t result, int error) = 0;
};


class TaskScalar: public Task {
    public:
        TaskScalar(const std::shared_ptr<DeviceOp> &op):
            Task(op)
        {}

        virtual void* buf() noexcept = 0;
        virtual size_t size() const noexcept = 0;
};


class TaskVector: public Task {
    public:
        TaskVector(const std::shared_ptr<DeviceOp> &op):
            Task(op)
        {}

        virtual iovec* iov() noexcept = 0;
        virtual unsigned int niov() const noexcept = 0;
        virtual size_t size() const noexcept = 0;
};


class TaskMessage: public Task {
    public:
        TaskMessage(const std::shared_ptr<DeviceOp> &op):
            Task(op)
        {}

        virtual msghdr* msg() noexcept = 0;
        virtual size_t size() const noexcept = 0;
        virtual int flags() const noexcept = 0;
};


void read(int fd, std::unique_ptr<TaskScalar> t) {
    int res = rawstor_fd_read(
        fd, t->buf(), t->size(),
        t->callback, t.get());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}


void read(int fd, std::unique_ptr<TaskMessage> t) {
    int res = rawstor_fd_recvmsg(
        fd, t->msg(), t->size(), t->flags(),
        t->callback, t.get());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}


void write(int fd, std::unique_ptr<TaskScalar> t) {
    int res = rawstor_fd_write(
        fd, t->buf(), t->size(),
        t->callback, t.get());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}


/*
void write(int fd, std::unique_ptr<TaskVector> t) {
    int res = rawstor_fd_writev(
        fd, t->iov(), t->niov(), t->size(),
        t->callback, t.get());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}
*/


void write(int fd, std::unique_ptr<TaskMessage> t) {
    int res = rawstor_fd_sendmsg(
        fd, t->msg(), t->size(), t->flags(),
        t->callback, t.get());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}


class TaskEventFd final: public TaskScalar {
    private:
        uint64_t _value;

    public:
        TaskEventFd(const std::shared_ptr<DeviceOp> &op, uint64_t value):
            TaskScalar(op),
            _value(value)
        {}

        void* buf() noexcept {
            return &_value;
        }

        size_t size() const noexcept {
            return sizeof(_value);
        }

        void operator()(size_t result, int error) {
            if (error) {
                RAWSTOR_THROW_SYSTEM_ERROR(error);
            }

            if (result != sizeof(uint64_t)) {
                rawstor_error("Unexpected eventfd size: %zu\n", result);
                RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
            }
        }
};


class TaskWriteMsg: public TaskMessage {
    private:
        iovec _iov[2];
        char _control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))];
        msghdr _msg;

    public:
        TaskWriteMsg(
            const std::shared_ptr<DeviceOp> &op,
            size_t payload_size,
            uint32_t flags,
            int nfds):
            TaskMessage(op),
            _iov {
                {
                    .iov_base = &op->header(),
                    .iov_len = sizeof(op->header()),
                },
                {
                    .iov_base = &op->payload(),
                    .iov_len = payload_size,
                }
            },
            _control {},
            _msg {
                .msg_name = nullptr,
                .msg_namelen = 0,
                .msg_iov = _iov,
                .msg_iovlen = 2,
                .msg_control = nullptr,
                .msg_controllen = 0,
                .msg_flags = 0,
            }
        {
            if (_iov[1].iov_len == 0) {
                _msg.msg_iovlen = 1;
            }

            VhostUserHeader &header = _op->header();

            header.flags = flags;
            header.flags &= ~VHOST_USER_VERSION_MASK;
            header.flags |= VHOST_USER_VERSION;
            header.flags |= VHOST_USER_REPLY_MASK;

            header.size = payload_size;

            const VhostUserFds &fds = _op->fds();
            assert(nfds <= VHOST_MEMORY_BASELINE_NREGIONS);
            if (nfds > 0) {
                size_t fdsize = nfds * sizeof(int);
                _msg.msg_controllen = CMSG_SPACE(fdsize);
                _msg.msg_control = &_control;
                struct cmsghdr *cmsg = CMSG_FIRSTHDR(&_msg);
                cmsg->cmsg_len = CMSG_LEN(fdsize);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                memcpy(CMSG_DATA(cmsg), fds.fds, fdsize);
            }
        }

        void operator()(size_t result, int error) override {
            if (error != 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(error);
            }

            if (result != size()) {
                rawstor_error("Unexpected response size: %zu\n", result);
                RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
            }

            rawstor_debug("Message sent: %zu bytes\n", result);
        }

        inline msghdr* msg() noexcept override {
            return &_msg;
        }

        size_t size() const noexcept override {
            return _iov[0].iov_len + _iov[1].iov_len;
        }

        inline int flags() const noexcept override {
            return 0;
        }

        virtual std::string str() const = 0;
};


class TaskWriteEmpty: public TaskWriteMsg {
    public:
        TaskWriteEmpty(const std::shared_ptr<DeviceOp> &op):
            TaskWriteMsg(op, 0, 0, 0)
        {}

        std::string str() const override {
            return "empty";
        }
};


class TaskWriteU64: public TaskWriteMsg {
    public:
        TaskWriteU64(const std::shared_ptr<DeviceOp> &op, uint64_t value):
            TaskWriteMsg(op, sizeof(op->payload().u64), 0, 0)
        {
            VhostUserPayload &payload = _op->payload();

            payload.u64 = value;
        }

        std::string str() const override {
            std::ostringstream oss;
            oss << "u64: 0x" << std::hex << _op->payload().u64;
            return oss.str();
        }
};


class TaskWriteConfig: public TaskWriteMsg {
    public:
        TaskWriteConfig(
            const std::shared_ptr<DeviceOp> &op,
            const VirtioBlkConfig &config):
            TaskWriteMsg(op, op->header().size, 0, 0)
        {
            VhostUserPayload &payload = _op->payload();
            assert(payload.config.size <= sizeof(VirtioBlkConfig));

            memcpy(payload.config.region, &config, payload.config.size);
        }

        std::string str() const override {
            std::ostringstream oss;
            VhostUserPayload &payload = _op->payload();

            oss << "config(" << payload.config.size << ")";
            return oss.str();
        }
};


class TaskWriteMemRegMsg: public TaskWriteMsg {
    public:
        TaskWriteMemRegMsg(
            const std::shared_ptr<DeviceOp> &op,
            const VhostUserMemRegMsg &msg):
            TaskWriteMsg(op, sizeof(TaskWriteMemRegMsg), 0, 0)
        {
            VhostUserPayload &payload = _op->payload();

            payload.memreg = msg;
        }

        std::string str() const override {
            return "memreg";
        }
};


void close_fds(VhostUserFds &fds) {
    for (unsigned int i = 0; i < fds.fd_num; ++i) {
        close(fds.fds[i]);
    }
}

/**
 * Get from the underlying vhost implementation the features bitmask. Feature
 * bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
 * VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
 */
std::unique_ptr<TaskWriteMsg> get_features(
    const std::shared_ptr<DeviceOp> &op)
{
    return std::make_unique<TaskWriteU64>(op, op->device().get_features());
}


/**
 * Enable features in the underlying vhost implementation using a bitmask.
 * Feature bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
 * VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
 */
std::unique_ptr<TaskWriteMsg> set_features(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserPayload &payload = op->payload();

    op->device().set_features(payload.u64);

    return nullptr;
}


/**
 * Issued when a new connection is established. It marks the sender as the
 * front-end that owns of the session. This can be used on the back-end as a
 * "session start" flag.
 */
std::unique_ptr<TaskWriteMsg> set_owner(
    const std::shared_ptr<DeviceOp> &)
{
    return nullptr;
}


/**
 * Set the size of the queue.
 */
std::unique_ptr<TaskWriteMsg> set_vring_num(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserPayload &payload = op->payload();

    unsigned int index = payload.state.index;
    unsigned int num = payload.state.num;

    rawstor_debug("State.index: %u\n", index);
    rawstor_debug("State.num:   %u\n", num);

    op->device().set_vring_size(index, num);

    return nullptr;
}


/**
 * Set the event file descriptor to signal when buffers are used. It is passed
 * in the ancillary data.
 *
 * Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD
 * flag. This flag is set when there is no file descriptor in the ancillary
 * data. This signals that polling will be used instead of waiting for the
 * call. Note that if the protocol features
 * VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS and
 * VHOST_USER_PROTOCOL_F_BACKEND_REQ have been negotiated this message isn't
 * necessary as the VHOST_USER_BACKEND_VRING_CALL message can be used, it may
 * however still be used to set an event file descriptor or to enable polling.
 */
std::unique_ptr<TaskWriteMsg> set_vring_call(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserHeader &header = op->header();
    const VhostUserPayload &payload = op->payload();
    VhostUserFds &fds = op->fds();

    int index = payload.u64 & VHOST_USER_VRING_IDX_MASK;
    bool nofd = payload.u64 & VHOST_USER_VRING_NOFD_MASK;
    int fd = nofd ? -1 : fds.fds[0];

    rawstor_debug("Got call_fd: %d for vq: %d\n", fd, index);

    if (nofd) {
        close_fds(fds);
    }

    if (fds.fd_num != 1) {
        rawstor_error("Invalid fds in request: %d", header.request);
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

    /* in case of I/O hang after reconnecting */
    if (fd != -1) {
        std::unique_ptr<TaskEventFd> t =
            std::make_unique<TaskEventFd>(op, 1);
        write(fd, std::move(t));
    }

    return nullptr;
}


/**
 * Set the event file descriptor to signal when error occurs. It is passed in
 * the ancillary data.
 *
 * Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid FD
 * flag. This flag is set when there is no file descriptor in the ancillary
 * data. Note that if the protocol
 * features VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS and
 * VHOST_USER_PROTOCOL_F_BACKEND_REQ have been negotiated this message isn't
 * necessary as the VHOST_USER_BACKEND_VRING_ERR message can be used, it may
 * however still be used to set an event file descriptor (which will be
 * preferred over the message).
 */
std::unique_ptr<TaskWriteMsg> set_vring_err(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserHeader &header = op->header();
    const VhostUserPayload &payload = op->payload();
    VhostUserFds &fds = op->fds();

    int index = payload.u64 & VHOST_USER_VRING_IDX_MASK;
    bool nofd = payload.u64 & VHOST_USER_VRING_NOFD_MASK;
    int fd = nofd ? -1 : fds.fds[0];

    rawstor_debug("Got err_fd: %d for vq: %d\n", fd, index);

    if (nofd) {
        close_fds(fds);
    }

    if (fds.fd_num != 1) {
        rawstor_error("Invalid fds in request: %d", header.request);
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
 * Get the protocol feature bitmask from the underlying vhost implementation.
 * Only legal if feature bit VHOST_USER_F_PROTOCOL_FEATURES is present in
 * VHOST_USER_GET_FEATURES. It does not need to be acknowledged by
 * VHOST_USER_SET_FEATURES.
 */
std::unique_ptr<TaskWriteMsg> get_protocol_features(
    const std::shared_ptr<DeviceOp> &op)
{
    return std::make_unique<TaskWriteU64>(
        op, op->device().get_protocol_features());
}


/**
 * Enable features in the underlying vhost implementation using a bitmask.
 * Feature bit VHOST_USER_F_PROTOCOL_FEATURES signals back-end support for
 * VHOST_USER_GET_PROTOCOL_FEATURES and VHOST_USER_SET_PROTOCOL_FEATURES.
 */
std::unique_ptr<TaskWriteMsg> set_protocol_features(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserPayload &payload = op->payload();

    rawstor_debug(
        "Setting features u64: 0x%llx\n",
        (unsigned long long)payload.u64);

    op->device().set_protocol_features(payload.u64);

    return nullptr;
}


/**
 * Query how many queues the back-end supports.
 *
 * This request should be sent only when VHOST_USER_PROTOCOL_F_MQ is set in
 * queried protocol features by VHOST_USER_GET_PROTOCOL_FEATURES.
 */
std::unique_ptr<TaskWriteMsg> get_queue_num(
    const std::shared_ptr<DeviceOp> &op)
{
    return std::make_unique<TaskWriteU64>(op, op->device().nqueues());
}


/**
 * Set the socket file descriptor for back-end initiated requests. It is passed
 * in the ancillary data.
 *
 * This request should be sent only when VHOST_USER_F_PROTOCOL_FEATURES has
 * been negotiated, and protocol feature bit VHOST_USER_PROTOCOL_F_BACKEND_REQ
 * bit is present in VHOST_USER_GET_PROTOCOL_FEATURES. If
 * VHOST_USER_PROTOCOL_F_REPLY_ACK is negotiated, the back-end must respond
 * with zero for success, non-zero otherwise.
 */
std::unique_ptr<TaskWriteMsg> set_backend_req_fd(
    const std::shared_ptr<DeviceOp> &op)
{
    VhostUserFds &fds = op->fds();

    if (fds.fd_num != 1) {
        rawstor_error(
            "Invalid backend_req_fd message (%d fd's)", fds.fd_num);
        close_fds(fds);
        return nullptr;
    }

    rawstor_debug("Got backend_fd: %d\n", fds.fds[0]);
    op->device().set_backend_fd(fds.fds[0]);

    return nullptr;
}


/**
 * When VHOST_USER_PROTOCOL_F_CONFIG is negotiated, this message is submitted
 * by the vhost-user front-end to fetch the contents of the virtio device
 * configuration space, vhost-user back-end's payload size MUST match the
 * front-end's request, vhost-user back-end uses zero length of payload to
 * indicate an error to the vhost-user front-end. The vhost-user front-end may
 * cache the contents to avoid repeated VHOST_USER_GET_CONFIG calls.
 */
std::unique_ptr<TaskWriteMsg> get_config(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserPayload &payload = op->payload();
    if (payload.config.size > sizeof(VirtioBlkConfig)) {
        /**
         * Return zero to indicate an error to frontend
         */
        return std::make_unique<TaskWriteEmpty>(op);
    }

    return std::make_unique<TaskWriteConfig>(op, op->device().get_config());
}


/**
 * When the VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS protocol feature has been
 * successfully negotiated, this message is submitted by the front-end to the
 * back-end. The back-end should return the message with a u64 payload
 * containing the maximum number of memory slots for QEMU to expose to the
 * guest. The value returned by the back-end will be capped at the maximum
 * number of ram slots which can be supported by the target platform.
 */
std::unique_ptr<TaskWriteMsg> get_max_mem_slots(
    const std::shared_ptr<DeviceOp> &op)
{
    return std::make_unique<TaskWriteU64>(op, op->device().get_max_mem_slots());
}


/**
 * When the VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS protocol feature has been
 * successfully negotiated, this message is submitted by the front-end to the
 * back-end. The message payload contains a memory region descriptor struct,
 * describing a region of guest memory which the back-end device must map in.
 * When the VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS protocol feature has been
 * successfully negotiated, along with the VHOST_USER_REM_MEM_REG message, this
 * message is used to set and update the memory tables of the back-end device.
 *
 * Exactly one file descriptor from which the memory is mapped is passed in the
 * ancillary data.
 *
 * In postcopy mode (see VHOST_USER_POSTCOPY_LISTEN), the back-end replies with
 * the bases of the memory mapped region to the front-end. For further details
 * on postcopy, see VHOST_USER_SET_MEM_TABLE. They apply to
 * VHOST_USER_ADD_MEM_REG accordingly.
 */
std::unique_ptr<TaskWriteMsg> add_mem_reg(
    const std::shared_ptr<DeviceOp> &op)
{
    const VhostUserHeader &header = op->header();
    VhostUserPayload &payload = op->payload();
    VhostUserFds &fds = op->fds();

    VhostUserMemRegMsg &m = payload.memreg;

    if (fds.fd_num != 1) {
        rawstor_error(
            "VHOST_USER_ADD_MEM_REG received %d fds - only 1 fd "
            "should be sent for this message type", fds.fd_num);
        close_fds(fds);
        return nullptr;
    }

    /*
     * If we are in postcopy mode and we receive a u64 payload with a 0 value
     * we know all the postcopy client bases have been received, and we
     * should start generating faults.
     */
    if (op->device().postcopy_listening() &&
        header.size == sizeof(payload.u64) &&
        payload.u64 == 0)
    {
        /**
         * TODO: Implement generate_faults.
         */
        // (void)generate_faults(dev);
        return nullptr;
    }

    if (header.size < sizeof(VhostUserMemoryRegion)) {
        rawstor_error(
            "VHOST_USER_ADD_MEM_REG requires a message size of at "
            "least %zu bytes and only %d bytes were received",
            sizeof(VhostUserMemoryRegion), header.size);
        close_fds(fds);
        return nullptr;
    }

    if (op->device().nregions() == VHOST_USER_MAX_RAM_SLOTS) {
        rawstor_error(
            "failing attempt to hot add memory via "
            "VHOST_USER_ADD_MEM_REG message because the backend has "
            "no free ram slots available");
        close_fds(fds);
        return nullptr;
    }

    m.region.userspace_addr = op->device().add_mem_reg(m.region, fds.fds[0]);

    close(fds.fds[0]);

    if (op->device().postcopy_listening()) {
        /* Send the message back to qemu with the addresses filled in. */
        rawstor_debug("Successfully added new region in postcopy\n");
        return std::make_unique<TaskWriteMemRegMsg>(op, m);
    }

    rawstor_debug("Successfully added new region\n");

    return nullptr;
}


std::unique_ptr<TaskWriteMsg> response(const std::shared_ptr<DeviceOp> &op) {
    switch (op->header().request) {
        case VHOST_USER_GET_FEATURES:
            return get_features(op);
        case VHOST_USER_SET_FEATURES:
            return set_features(op);
        case VHOST_USER_SET_OWNER:
            return set_owner(op);
        case VHOST_USER_SET_VRING_NUM:
            return set_vring_num(op);
        case VHOST_USER_SET_VRING_CALL:
            return set_vring_call(op);
        case VHOST_USER_SET_VRING_ERR:
            return set_vring_err(op);
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
        case VHOST_USER_GET_MAX_MEM_SLOTS:
            return get_max_mem_slots(op);
        case VHOST_USER_ADD_MEM_REG:
            return add_mem_reg(op);
        default:
            rawstor_error("Unexpected request: %d\n", op->header().request);
            throw std::runtime_error("Unexpected request");
            return nullptr;
    };
}


void dispatch(const std::shared_ptr<DeviceOp> &op) {
    VhostUserHeader &header = op->header();

    rawstor_debug("============= Vhost user message =============\n");
    rawstor_debug("Request: %d\n", header.request);
    rawstor_debug("Flags:   0x%x\n", header.flags);
    rawstor_debug("Size:    %u\n", header.size);

#if RAWSTOR_LOGLEVEL >= RAWSTOR_LOGLEVEL_DEBUG
    VhostUserFds &fds = op->fds();
    if (fds.fd_num) {
        std::ostringstream oss;
        for (unsigned int i = 0; i < fds.fd_num; i++) {
            oss << " " << fds.fds[i];
        }
        rawstor_debug("Fds:    %s\n", oss.str().c_str());
    }
#endif

    rawstor_debug("==============================================\n");

    bool need_reply = header.flags & VHOST_USER_NEED_REPLY_MASK;

    std::unique_ptr<TaskWriteMsg> t = response(op);
    if (t.get() == nullptr && need_reply) {
        t = std::make_unique<TaskWriteU64>(op, 0);
    }
    if (t.get() != nullptr) {
        rawstor_debug("Sending back to guest: %s\n", t->str().c_str());
        write(op->device().fd(), std::move(t));
    }
}


class TaskReadUserHeader final: public TaskMessage {
    private:
        /**
         * TODO: Move these variables to DriverOp.
         */
        iovec _iov;
        char _control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))];
        msghdr _msg;

    public:
        TaskReadUserHeader(const std::shared_ptr<DeviceOp> &op):
            TaskMessage(op),
            _iov {
                .iov_base = &_op->header(),
                .iov_len = sizeof(_op->header())
            },
            _msg {
                .msg_name = nullptr,
                .msg_namelen = 0,
                .msg_iov = &_iov,
                .msg_iovlen = 1,
                .msg_control = &_control,
                .msg_controllen = sizeof(_control),
                .msg_flags = 0,
            }
        {}

        inline msghdr* msg() noexcept override {
            return &_msg;
        }

        size_t size() const noexcept override {
            return sizeof(_op->header());
        }

        inline int flags() const noexcept override {
            return MSG_WAITALL;
        }

        void operator()(size_t result, int error) override;
};


class TaskReadUserPayload final: public TaskScalar {
    private:
        size_t _payload_size;

    public:
        TaskReadUserPayload(
            const std::shared_ptr<DeviceOp> &op,
            size_t payload_size):
            TaskScalar(op),
            _payload_size(payload_size)
        {}

        inline void* buf() noexcept override {
            return &_op->payload();
        }

        size_t size() const noexcept override {
            return _payload_size;
        }

        void operator()(size_t result, int error) override;
};


void TaskReadUserHeader::operator()(size_t result, int error) {
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (result != size()) {
        rawstor_error("Unexpected request header size: %zu\n", result);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    VhostUserFds &fds = _op->fds();
    fds.fd_num = 0;
    cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&_msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&_msg, cmsg))
    {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            size_t fd_size = cmsg->cmsg_len - CMSG_LEN(0);
            fds.fd_num = fd_size / sizeof(int);
            assert(fds.fd_num <= VHOST_MEMORY_BASELINE_NREGIONS);
            memcpy(fds.fds, CMSG_DATA(cmsg), fd_size);
            break;
        }
    }

    const VhostUserHeader &header = _op->header();
    if (header.size != 0) {
        if (header.size > sizeof(VhostUserPayload)) {
            rawstor_error(
                "Unexpected request payload size: %u\n",
                (unsigned int)header.size);
            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }
        std::unique_ptr<TaskReadUserPayload> t =
            std::make_unique<TaskReadUserPayload>(
                _op, header.size);
        read(_op->device().fd(), std::move(t));
        return;
    }

    dispatch(_op);

    std::shared_ptr<DeviceOp> op =
        std::make_shared<DeviceOp>(_op->device());
    std::unique_ptr<TaskReadUserHeader> t =
        std::make_unique<TaskReadUserHeader>(op);
    read(op->device().fd(), std::move(t));
}


void TaskReadUserPayload::operator()(size_t result, int error) {
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (result != size()) {
        rawstor_error("Unexpected request payload size: %zu\n", result);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    dispatch(_op);

    std::shared_ptr<DeviceOp> op =
        std::make_shared<DeviceOp>(_op->device());
    std::unique_ptr<TaskReadUserHeader> t =
        std::make_unique<TaskReadUserHeader>(op);
    read(op->device().fd(), std::move(t));
}


size_t find_mem_region_pos(
    const std::vector<std::unique_ptr<rawstor::vhost::DevRegion>> &regions,
    const VhostUserMemoryRegion &m)
{
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
        size_t mid = low + (high - low)  / 2;
        const rawstor::vhost::DevRegion &cur = *regions[mid];

        /* Overlap of GPA addresses. */
        if (
            start_gpa < cur.guest_phys_addr() + cur.memory_size() &&
            cur.guest_phys_addr() < end_gpa)
        {
            throw std::runtime_error(
                "regions with overlapping guest physical addresses");
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


} // unnamed

namespace rawstor {
namespace vhost {


Device::~Device() {
    if (_backend_fd != -1) {
        try {
            if (close(_backend_fd)) {
                RAWSTOR_THROW_ERRNO();
            }
        } catch (std::exception &e) {
            std::ostringstream oss;
            oss << "Failed to close backend fd: " << e.what();
            rawstor_error("%s\n", oss.str().c_str());
        }
    }
    try {
        if (close(_fd)) {
            RAWSTOR_THROW_ERRNO();
        }
    } catch (std::exception &e) {
        std::ostringstream oss;
        oss << "Failed to close socket: " << e.what();
        rawstor_error("%s\n", oss.str().c_str());
    }
}


uint64_t Device::get_features() const noexcept {
    return
        /**
         * The following VIRTIO feature bits are supported by our virtqueue
         * implementation:
         */
        1ull << VIRTIO_F_NOTIFY_ON_EMPTY |
        1ull << VIRTIO_RING_F_INDIRECT_DESC |
        1ull << VIRTIO_RING_F_EVENT_IDX |
        1ull << VIRTIO_F_VERSION_1 |

        /**
         * vhost-user feature bits
         */
        1ull << VHOST_F_LOG_ALL |
        1ull << VHOST_USER_F_PROTOCOL_FEATURES |

        /*
        1ull << VIRTIO_BLK_F_SIZE_MAX |
        1ull << VIRTIO_BLK_F_SEG_MAX |
        1ull << VIRTIO_BLK_F_TOPOLOGY |
        1ull << VIRTIO_BLK_F_BLK_SIZE |
        1ull << VIRTIO_BLK_F_FLUSH |
        1ull << VIRTIO_BLK_F_CONFIG_WCE |

        1ull << VIRTIO_BLK_F_GEOMETRY |
        1ull << VIRTIO_BLK_F_MQ |
        1ull << VIRTIO_BLK_F_DISCARD |
        1ull << VIRTIO_BLK_F_WRITE_ZEROES |
        1ull << VIRTIO_BLK_F_SECURE_ERASE |
        1ull << VIRTIO_BLK_F_ZONED;
        */

        _features;
    }


void Device::set_features(uint64_t features) {
    if (!(features & (1ull << VIRTIO_F_VERSION_1))) {
        throw std::runtime_error(
            "virtio legacy devices aren't supported by libvhost-user");
    }

    _features = features;

    if (!(_features & (1ull << VHOST_USER_F_PROTOCOL_FEATURES))) {
        for (auto &vq: _vqs) {
            vq.enable();
        }
    }

}


uint64_t Device::get_protocol_features() const noexcept {
    return
        /*
        * Note that we support, but intentionally do not set,
        * VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS. This means that
        * a device implementation can return it in its callback
        * (get_protocol_features) if it wants to use this for
        * simulation, but it is otherwise not desirable (if even
        * implemented by the frontend.)
        */
        (
            1ull << VHOST_USER_PROTOCOL_F_MQ |
            1ull << VHOST_USER_PROTOCOL_F_LOG_SHMFD |
            1ull << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
            1ull << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER |
            1ull << VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD |
            1ull << VHOST_USER_PROTOCOL_F_REPLY_ACK |
            1ull << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
            1ull << VHOST_USER_PROTOCOL_F_CONFIG
        ) |
        _protocol_features;
}


void Device::set_vring_size(size_t index, unsigned int size) {
    if (index >= _vqs.size()) {
        std::ostringstream oss;
        oss << "Invalid queue index: " << index;
        throw std::out_of_range(oss.str());
    }

    _vqs[index].set_vring_size(size);
}


void Device::set_vring_call(size_t index, int fd) {
    if (index >= _vqs.size()) {
        std::ostringstream oss;
        oss << "Invalid queue index: " << index;
        throw std::out_of_range(oss.str());
    }

    _vqs[index].set_call_fd(fd);
}


void Device::set_vring_err(size_t index, int fd) {
    if (index >= _vqs.size()) {
        std::ostringstream oss;
        oss << "Invalid queue index: " << index;
        throw std::out_of_range(oss.str());
    }

    _vqs[index].set_err_fd(fd);
}


uint64_t Device::add_mem_reg(const VhostUserMemoryRegion &m, int fd) {
    if (_regions.size() >= VHOST_USER_MAX_RAM_SLOTS) {
        throw std::runtime_error(
            "failing attempt to hot add memory region because the backend has "
            "no free ram slots available");
    }

    size_t idx = find_mem_region_pos(_regions, m);

    std::unique_ptr<DevRegion> region =
        std::make_unique<DevRegion>(m, fd, _postcopy_listening);

    rawstor_debug("Adding region %zu\n", _regions.size());
    rawstor_debug(
        "    guest_phys_addr: 0x%llx\n",
        (unsigned long long)m.guest_phys_addr);
    rawstor_debug(
        "    memory_size:     0x%llx\n",
        (unsigned long long)m.memory_size);
    rawstor_debug(
        "    userspace_addr:  0x%llx\n",
        (unsigned long long)m.userspace_addr);
    rawstor_debug(
        "    old mmap_offset: 0x%llx\n",
        (unsigned long long)m.mmap_offset);
    rawstor_debug(
        "    new mmap_offset: 0x%llx\n",
        (unsigned long long)region->mmap_offset());
    rawstor_debug(
        "    mmap_addr:       0x%llx\n",
        (unsigned long long)(uintptr_t)region->mmap_addr());

    /**
     * Return the address to QEMU so that it can translate the ufd fault
     * addresses back.
     */
    uint64_t ret = _postcopy_listening ?
        (uint64_t)(uintptr_t)region->mmap_addr() + region->mmap_offset() :
        m.userspace_addr;

    _regions.insert(_regions.begin() + idx, std::move(region));

    return ret;
}


void Device::loop() {
    std::shared_ptr<DeviceOp> op = std::make_shared<DeviceOp>(*this);
    std::unique_ptr<TaskReadUserHeader> t =
        std::make_unique<TaskReadUserHeader>(op);
    read(_fd, std::move(t));

    while (!rawstor_empty()) {
        int res = rawstor_wait();
        if (res) {
            if (res == -ETIME) {
                rawstor_warning("rawstor_wait() failed: timeout\n");
                continue;
            }

            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }
}


}} // rawstor::vhost
