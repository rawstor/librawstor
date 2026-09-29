#include "client.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <unistd.h>

#include <stdexcept>

#include <cstring>

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

namespace rawstor {
namespace ostserver {
namespace tests {

Client::Client(int fd) : _fd(fd), _next_cid(0) {
}

Client::~Client() {
    if (_fd != -1) {
        ::close(_fd);
    }
}

uint16_t
Client::send_allocate(const RawstdUUID& id, uint64_t size, unsigned int width) {
    uint16_t cid = _next_cid++;
    RawstorFrameAllocate frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_ALLOCATE,
                .cid = cid,
            },
        .payload = {
            .object_id = {},
            .chunk_offset = 0,
            .size = size,
            .stripe_width = 0,
            .chunk_shift = 0,
            .failure_domain = 0,
            .width = static_cast<uint8_t>(width),
            .member_role = 0, /* RAWSTOR_MEMBER_DATA, <rawstor/target.h> */
            .reserved2 = 0,
        },
    };
    std::memcpy(frame.payload.object_id, id.bytes, sizeof(id.bytes));
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t Client::send_set_object(const RawstdUUID& id) {
    uint16_t cid = _next_cid++;
    RawstorFrameBasic frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_SET_OBJECT,
                .cid = cid,
            },
        .payload = {.object_id = {}, .offset = 0, .snapshot_id = {}, .val = 0},
    };
    std::memcpy(frame.payload.object_id, id.bytes, sizeof(id.bytes));
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t
Client::send_write(uint64_t offset, const void* buf, size_t size, bool sync) {
    uint16_t cid = _next_cid++;
    RawstorFrameIO frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_WRITE,
                .cid = cid,
            },
        .payload = {
            .offset = offset,
            .hash = rawstd_hash_scalar(buf, size),
            .len = static_cast<uint32_t>(size),
            .flags = static_cast<uint8_t>(sync ? RAWSTOR_FLAG_SYNC : 0),
        },
    };
    send_all(_fd, &frame, sizeof(frame));
    send_all(_fd, buf, size);
    return cid;
}

uint16_t Client::send_read(uint64_t offset, uint32_t size) {
    uint16_t cid = _next_cid++;
    RawstorFrameIO frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_READ,
                .cid = cid,
            },
        .payload = {.offset = offset, .hash = 0, .len = size, .flags = 0},
    };
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t Client::send_discard(uint64_t offset, uint32_t size) {
    uint16_t cid = _next_cid++;
    RawstorFrameIO frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_DISCARD,
                .cid = cid,
            },
        .payload = {.offset = offset, .hash = 0, .len = size, .flags = 0},
    };
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t Client::send_write_zeroes(
    uint64_t offset, uint32_t size, bool unmap, bool sync
) {
    uint16_t cid = _next_cid++;
    uint8_t flags = static_cast<uint8_t>(
        (unmap ? RAWSTOR_FLAG_UNMAP : 0) | (sync ? RAWSTOR_FLAG_SYNC : 0)
    );
    RawstorFrameIO frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_WRITE_ZEROES,
                .cid = cid,
            },
        .payload = {
            .offset = offset,
            .hash = 0,
            .len = size,
            .flags = flags,
        },
    };
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t Client::send_list(const RawstdUUID& token, uint32_t limit) {
    uint16_t cid = _next_cid++;
    RawstorFrameList frame = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_LIST,
                .cid = cid,
            },
        .payload = {.token_id = {}, .limit = limit},
    };
    std::memcpy(frame.payload.token_id, token.bytes, sizeof(token.bytes));
    send_all(_fd, &frame, sizeof(frame));
    return cid;
}

uint16_t Client::send_unknown_command() {
    uint16_t cid = _next_cid++;
    RawstorFrameHead head = {
        .magic = RAWSTOR_MAGIC,
        .cmd = 9999,
        .cid = cid,
    };
    send_all(_fd, &head, sizeof(head));
    return cid;
}

RawstorFrameResponse Client::recv_response(void* payload, size_t payload_size) {
    RawstorFrameResponse response;
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
} // namespace ostserver
} // namespace rawstor
