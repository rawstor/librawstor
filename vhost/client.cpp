#include "client.hpp"

extern "C" {
#include "libvhost-user.h"
}

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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


// class ClientOp {
//     private:
//         rawstor::vhost::Client &_client;
//         VhostUserHeader _header;
//         VhostUserPayload _payload;
//         VhostUserFds _fds;
// 
//     public:
//         ClientOp(rawstor::vhost::Client &client):
//             _client(client)
//         {}
//         ClientOp(const ClientOp &) = delete;
//         ClientOp(ClientOp &&) = delete;
//         ClientOp& operator=(const ClientOp &) = delete;
//         ClientOp& operator=(ClientOp &&) = delete;
// 
//         inline rawstor::vhost::Client& client() noexcept {
//             return _client;
//         }
// 
//         inline VhostUserHeader& header() noexcept {
//             return _header;
//         }
// 
//         inline VhostUserPayload& payload() noexcept {
//             return _payload;
//         }
// 
//         inline VhostUserFds& fds() noexcept {
//             return _fds;
//         }
// };
// 
// 
// class Task {
//     protected:
//         std::shared_ptr<ClientOp> _op;
// 
//     public:
//         static int callback(size_t result, int error, void *data) {
//             std::unique_ptr<Task> t(static_cast<Task*>(data));
//             try {
//                 (*t)(result, error);
//                 return 0;
//             } catch (std::system_error &e) {
//                 return -e.code().value();
//             }
//         }
// 
//         Task(const std::shared_ptr<ClientOp> &op):
//             _op(op)
//         {}
//         Task(const Task &) = delete;
//         Task(Task &&) = delete;
//         virtual ~Task() {}
// 
//         Task& operator=(const Task &) = delete;
//         Task& operator=(Task &&) = delete;
// 
//         virtual void operator()(size_t result, int error) = 0;
// };
// 
// 
// class TaskScalar: public Task {
//     public:
//         TaskScalar(const std::shared_ptr<ClientOp> &op):
//             Task(op)
//         {}
// 
//         virtual void* buf() noexcept = 0;
//         virtual size_t size() const noexcept = 0;
// };
// 
// 
// class TaskVector: public Task {
//     public:
//         TaskVector(const std::shared_ptr<ClientOp> &op):
//             Task(op)
//         {}
// 
//         virtual iovec* iov() noexcept = 0;
//         virtual unsigned int niov() const noexcept = 0;
//         virtual size_t size() const noexcept = 0;
// };
// 
// 
// void read(int fd, std::unique_ptr<TaskScalar> t) {
//     int res = rawstor_fd_read(
//         fd, t->buf(), t->size(),
//         t->callback, t.get());
//     if (res) {
//         RAWSTOR_THROW_SYSTEM_ERROR(-res);
//     }
//     t.release();
// }
// 
// 
// void write(int fd, std::unique_ptr<TaskVector> t) {
//     int res = rawstor_fd_writev(
//         fd, t->iov(), t->niov(), t->size(),
//         t->callback, t.get());
//     if (res) {
//         RAWSTOR_THROW_SYSTEM_ERROR(-res);
//     }
//     t.release();
// }
// 
// 
// class TaskWriteMsg: public TaskVector {
//     private:
//         iovec _iov[2];
// 
//     public:
//         TaskWriteMsg(
//             const std::shared_ptr<ClientOp> &op,
//             size_t payload_size):
//             TaskVector(op),
//             _iov {
//                 {
//                     .iov_base = &op->header(),
//                     .iov_len = sizeof(op->header()),
//                 },
//                 {
//                     .iov_base = &op->payload(),
//                     .iov_len = payload_size,
//                 }
//             }
//         {
//             op->header().size = payload_size;
//             op->header().flags = VHOST_USER_VERSION | VHOST_USER_REPLY_MASK;
//         }
// 
//         void operator()(size_t result, int error) override {
//             if (error != 0) {
//                 RAWSTOR_THROW_SYSTEM_ERROR(error);
//             }
// 
//             if (result != size()) {
//                 rawstor_error("Unexpected response size: %zu\n", result);
//                 RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
//             }
// 
//             rawstor_debug("Message sent: %zu bytes\n", result);
//         }
// 
//         iovec* iov() noexcept override {
//             return _iov;
//         }
// 
//         unsigned int niov() const noexcept override {
//             return 2;
//         }
// 
//         size_t size() const noexcept override {
//             return _iov[0].iov_len + _iov[1].iov_len;
//         }
// 
//         virtual std::string str() const = 0;
// };
// 
// 
// class TaskWriteU64: public TaskWriteMsg {
//     public:
//         TaskWriteU64(const std::shared_ptr<ClientOp> &op, uint64_t u64):
//             TaskWriteMsg(op, sizeof(op->payload().u64))
//         {
//             _op->payload().u64 = u64;
//         }
// 
//         std::string str() const override {
//             std::ostringstream oss;
//             oss << "u64: 0x" << std::hex << _op->payload().u64;
//             return oss.str();
//         }
// };
// 
// 
// class TaskWriteGetFeatures final: public TaskWriteU64 {
//     public:
//         TaskWriteGetFeatures(const std::shared_ptr<ClientOp> &op):
//             TaskWriteU64(
//                 op,
//                 /*
//                  * The following VIRTIO feature bits are supported by our
//                  * virtqueue implementation:
//                  */
//                 1ull << VIRTIO_F_NOTIFY_ON_EMPTY |
//                 1ull << VIRTIO_RING_F_INDIRECT_DESC |
//                 1ull << VIRTIO_RING_F_EVENT_IDX |
//                 1ull << VIRTIO_F_VERSION_1 |
// 
//                 /* vhost-user feature bits */
//                 1ull << VHOST_F_LOG_ALL |
//                 1ull << VHOST_USER_F_PROTOCOL_FEATURES
//             )
//         {}
// };
// 
// 
// class TaskWriteGetProtocolFeatures final: public TaskWriteU64 {
//     public:
//         TaskWriteGetProtocolFeatures(const std::shared_ptr<ClientOp> &op):
//             TaskWriteU64(
//                 op,
//                 /*
//                 * Note that we support, but intentionally do not set,
//                 * VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS. This means that
//                 * a device implementation can return it in its callback
//                 * (get_protocol_features) if it wants to use this for
//                 * simulation, but it is otherwise not desirable (if even
//                 * implemented by the frontend.)
//                 */
//                 (
//                     1ull << VHOST_USER_PROTOCOL_F_MQ |
//                     1ull << VHOST_USER_PROTOCOL_F_LOG_SHMFD |
//                     1ull << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
//                     1ull << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER |
//                     1ull << VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD |
//                     1ull << VHOST_USER_PROTOCOL_F_REPLY_ACK |
//                     1ull << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
//                     1ull << VHOST_USER_PROTOCOL_F_CONFIG
//                 ) |
//                 op->client().get_features()
//             )
//         {}
// };
// 
// 
// std::unique_ptr<TaskWriteMsg> response(const std::shared_ptr<ClientOp> &op) {
//     switch (op->header().request) {
//         case VHOST_USER_GET_FEATURES:
//             return std::make_unique<TaskWriteGetFeatures>(op);
//         case VHOST_USER_GET_PROTOCOL_FEATURES:
//             return std::make_unique<TaskWriteGetProtocolFeatures>(op);
//         case VHOST_USER_SET_PROTOCOL_FEATURES:
//             {
//                 rawstor_debug(
//                     "Setting features u64: 0x%llx\n", op->payload().u64);
//                 op->client().set_features(op->payload().u64);
//                 return nullptr;
//             }
//         case VHOST_USER_GET_QUEUE_NUM:
//             return std::make_unique<TaskWriteU64>(op, 1);
//         // case VHOST_USER_SET_BACKEND_REQ_FD:
//         case VHOST_USER_GET_MAX_MEM_SLOTS:
//             return std::make_unique<TaskWriteU64>(
//                 op, op->client().get_max_mem_slots());
//         default:
//             rawstor_error("Unexpected request: %d\n", op->header().request);
//             return nullptr;
//     };
// 
//     // if (op->header().flags & VHOST_USER_NEED_REPLY_MASK) {
//     //     msg->payload.u64 = 0;
//     //     msg->size = sizeof(msg->payload.u64);
//     //     msg->fd_num = 0;
//     //     response = 1;
//     // }
// }
// 
// 
// void dispatch(const std::shared_ptr<ClientOp> &op) {
//     rawstor_debug("============= Vhost user message =============\n");
//     rawstor_debug("Request: %d\n", op->header().request);
//     rawstor_debug("Flags:   0x%x\n", op->header().flags);
//     rawstor_debug("Size:    %u\n", op->header().size);
// 
//     std::unique_ptr<TaskWriteMsg> t = response(op);
//     if (t.get() != nullptr) {
//         rawstor_debug(
//             "Sending back to guest %s\n", t->str().c_str());
//         write(op->client().fd(), std::move(t));
//     }
// 
//     rawstor_debug("==============================================\n");
// }
// 
// 
// class TaskReadUserHeader final: public TaskScalar {
//     public:
//         TaskReadUserHeader(const std::shared_ptr<ClientOp> &op):
//             TaskScalar(op)
//         {}
// 
//         inline void* buf() noexcept override {
//             return &_op->header();
//         }
// 
//         size_t size() const noexcept override {
//             return sizeof(_op->header());
//         }
// 
//         void operator()(size_t result, int error) override;
// };
// 
// 
// class TaskReadUserPayload final: public TaskScalar {
//     private:
//         size_t _payload_size;
// 
//     public:
//         TaskReadUserPayload(
//             const std::shared_ptr<ClientOp> &op,
//             size_t payload_size):
//             TaskScalar(op),
//             _payload_size(payload_size)
//         {}
// 
//         inline void* buf() noexcept override {
//             return &_op->payload();
//         }
// 
//         size_t size() const noexcept override {
//             return _payload_size;
//         }
// 
//         void operator()(size_t result, int error) override;
// };
// 
// 
// void TaskReadUserHeader::operator()(size_t result, int error) {
//     if (error != 0) {
//         RAWSTOR_THROW_SYSTEM_ERROR(error);
//     }
// 
//     if (result != size()) {
//         rawstor_error("Unexpected request header size: %zu\n", result);
//         RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
//     }
// 
//     if (_op->header().size != 0) {
//         if (_op->header().size > sizeof(VhostUserPayload)) {
//             rawstor_error(
//                 "Unexpected request payload size: %u\n",
//                 (unsigned int)_op->header().size);
//             RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
//         }
//         std::unique_ptr<TaskReadUserPayload> t =
//             std::make_unique<TaskReadUserPayload>(
//                 _op, _op->header().size);
//         read(_op->client().fd(), std::move(t));
//         return;
//     }
// 
//     dispatch(_op);
// 
//     std::shared_ptr<ClientOp> op =
//         std::make_shared<ClientOp>(_op->client());
//     std::unique_ptr<TaskReadUserHeader> t =
//         std::make_unique<TaskReadUserHeader>(op);
//     read(op->client().fd(), std::move(t));
// }
// 
// 
// void TaskReadUserPayload::operator()(size_t result, int error) {
//     if (error != 0) {
//         RAWSTOR_THROW_SYSTEM_ERROR(error);
//     }
// 
//     if (result != size()) {
//         rawstor_error("Unexpected request payload size: %zu\n", result);
//         RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
//     }
// 
//     dispatch(_op);
// 
//     std::shared_ptr<ClientOp> op =
//         std::make_shared<ClientOp>(_op->client());
//     std::unique_ptr<TaskReadUserHeader> t =
//         std::make_unique<TaskReadUserHeader>(op);
//     read(op->client().fd(), std::move(t));
// }


void panic(VuDev *, const char *) {
    abort();
}

void set_watch(VuDev *, int, int, vu_watch_cb, void *) {
    abort();
}

void remove_watch(VuDev *, int) {
    abort();
}



} // unnamed

namespace rawstor {
namespace vhost {

Client::Client(int fd):
    _fd(fd),
    _backend_fd(-1),
    _features(0)
{
    VuDev dev;
    bool res = vu_init(
        &dev, 2, _fd, panic, nullptr, set_watch, remove_watch, nullptr);
    assert(res == true);
    vu_deinit(&dev);
}


Client::~Client() {
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


void Client::loop() {
    /*
    std::shared_ptr<ClientOp> op = std::make_shared<ClientOp>(*this);
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
    */
}


}} // rawstor::vhost
