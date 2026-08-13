#include "client.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <unistd.h>

#include <stdexcept>

#include <cstring>

namespace rawstor {
namespace ostbackend {
namespace tests {

namespace {

void send_all(int fd, const void* buf, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < size) {
        ssize_t res = ::send(fd, p + sent, size - sent, 0);
        if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }
        sent += static_cast<size_t>(res);
    }
}

void recv_all(int fd, void* buf, size_t size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < size) {
        ssize_t res = ::recv(fd, p + got, size - got, 0);
        if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }
        if (res == 0) {
            throw std::runtime_error("Client: peer closed the connection");
        }
        got += static_cast<size_t>(res);
    }
}

} // namespace

Client::Client(int fd) : _fd(fd), _next_cid(0) {
}

Client::~Client() {
    if (_fd != -1) {
        ::close(_fd);
    }
}

uint16_t Client::send_allocate(const RawstdUUID& id, uint64_t size) {
    uint16_t cid = _next_cid++;
    RawstorOSTFrameBasic frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_ALLOCATE,
                .cid = cid,
            },
        .body = {.obj_id = {}, .offset = 0, .val = size},
    };
    std::memcpy(frame.body.obj_id, id.bytes, sizeof(id.bytes));
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t Client::send_set_object(const RawstdUUID& id) {
    uint16_t cid = _next_cid++;
    RawstorOSTFrameBasic frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_SET_OBJECT,
                .cid = cid,
            },
        .body = {.obj_id = {}, .offset = 0, .val = 0},
    };
    std::memcpy(frame.body.obj_id, id.bytes, sizeof(id.bytes));
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t
Client::send_write(uint64_t offset, const void* buf, size_t size, bool sync) {
    uint16_t cid = _next_cid++;
    RawstorOSTFrameIO frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_WRITE,
                .cid = cid,
            },
        .body = {
            .offset = offset,
            .len = static_cast<uint32_t>(size),
            .hash = rawstd_hash_scalar(buf, size),
            .sync = static_cast<uint8_t>(sync ? 1 : 0),
        },
    };
    send_all(_fd, &frame, sizeof(frame));
    send_all(_fd, buf, size);
    return cid;
}

uint16_t Client::send_read(uint64_t offset, uint32_t size) {
    uint16_t cid = _next_cid++;
    RawstorOSTFrameIO frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_READ,
                .cid = cid,
            },
        .body = {.offset = offset, .len = size, .hash = 0, .sync = 0},
    };
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

RawstorOSTFrameResponse
Client::recv_response(void* payload, size_t payload_size) {
    RawstorOSTFrameResponse response;
    recv_all(_fd, &response, sizeof(response));
    if (payload_size > 0) {
        recv_all(_fd, payload, payload_size);
    }
    return response;
}

size_t Client::bytes_available() const {
    int n = 0;
    if (::ioctl(_fd, FIONREAD, &n) == -1) {
        RAWSTD_THROW_ERRNO();
    }
    return static_cast<size_t>(n);
}

} // namespace tests
} // namespace ostbackend
} // namespace rawstor
