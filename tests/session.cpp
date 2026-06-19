#include "session.hpp"

#include "server.hpp"

#include <rawstor/ost_protocol.h>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>

#include <stdexcept>

#include <cassert>

namespace rawstor {
namespace tests {

Session::Session(rawstor::tests::Server& server) : _server(server) {
    _server.accept("SESSION <<<");
}

Session::~Session() {
    _server.close("SESSION >>>");
}

void Session::cmd_allocate_request() {
}

void Session::cmd_allocate_response() {
}

void Session::cmd_allocate() {
}

void Session::cmd_set_object_request() {
    _server.read(
        "RAWSTOR_CMD_SET_OBJECT <<<", sizeof(RawstorOSTFrameBasic),
        [](const void*, size_t result) {
            if (result == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
            }
            if (result != sizeof(RawstorOSTFrameBasic)) {
                throw std::runtime_error("Partial read");
            }
        }
    );
}

void Session::cmd_set_object_response(
    uint32_t magic, uint16_t cid, int32_t res
) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = cid,
        },
        .body = {
            .res = res,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_SET_OBJECT >>>", &response, sizeof(response));
}

void Session::cmd_set_object(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_set_object_request();
    cmd_set_object_response(magic, cid, res);
}

void Session::cmd_read_request() {
    _server.read(
        "RAWSTOR_CMD_READ <<<", sizeof(RawstorOSTFrameIO),
        [](const void*, size_t result) {
            if (result == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
            }
            if (result != sizeof(RawstorOSTFrameIO)) {
                throw std::runtime_error("Partial read");
            }
        }
    );
}

void Session::cmd_read_response(
    uint32_t magic, uint16_t cid, const void* buf, size_t size, uint64_t hash
) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_READ,
            .cid = cid,
        },
        .body = {
            .res = static_cast<int32_t>(size),
            .hash = hash,
        },
    };
    iovec iov[2] = {
        {
            .iov_base = &response,
            .iov_len = sizeof(response),
        },
        {
            .iov_base = const_cast<void*>(buf),
            .iov_len = size,
        },
    };
    _server.writev("RAWSTOR_CMD_READ >>>", iov, sizeof(iov) / sizeof(iov[0]));
}

void Session::cmd_read_response(
    uint32_t magic, uint16_t cid, const void* buf, size_t size
) {
    cmd_read_response(magic, cid, buf, size, rawstd_hash_scalar(buf, size));
}

void Session::cmd_read(
    uint32_t magic, uint16_t cid, const void* buf, size_t size, uint64_t hash
) {
    cmd_read_request();
    cmd_read_response(magic, cid, buf, size, hash);
}

void Session::cmd_read(
    uint32_t magic, uint16_t cid, const void* buf, size_t size
) {
    cmd_read_request();
    cmd_read_response(magic, cid, buf, size);
}

void Session::cmd_write_request(size_t size) {
    _server.read(
        "RAWSTOR_CMD_WRITE <<<", sizeof(RawstorOSTFrameIO) + size,
        [size](const void*, size_t result) {
            if (result == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
            }
            if (result != sizeof(RawstorOSTFrameIO) + size) {
                throw std::runtime_error("Partial read");
            }
        }
    );
}

void Session::cmd_write_response(uint32_t magic, uint16_t cid, int32_t res) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = cid,
        },
        .body = {
            .res = res,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_WRITE >>>", &response, sizeof(response));
}

void Session::cmd_write(uint32_t magic, uint16_t cid, int32_t res) {
    assert(res > 0);
    cmd_write_request(static_cast<size_t>(res));
    cmd_write_response(magic, cid, res);
}

} // namespace tests
} // namespace rawstor
