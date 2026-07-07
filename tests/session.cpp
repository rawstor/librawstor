#include "session.hpp"

#include "server.hpp"

#include <rawstor/protocol.h>

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
    _server.read(
        "RAWSTOR_CMD_ALLOCATE <<<", sizeof(RawstorOSTFrameAllocate),
        [](const void*) {}
    );
}

void Session::cmd_allocate_response(uint32_t magic, uint16_t cid, int32_t res) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_ALLOCATE,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = 0,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_ALLOCATE >>>", &response, sizeof(response));
}

void Session::cmd_allocate(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_allocate_request();
    cmd_allocate_response(magic, cid, res);
}

void Session::cmd_set_object_request() {
    _server.read(
        "RAWSTOR_CMD_SET_OBJECT <<<", sizeof(RawstorOSTFrameSetObject),
        [](const void*) {}
    );
}

void Session::cmd_set_object_response(
    uint32_t magic, uint16_t cid, int32_t res
) {
    if (res < 0) {
        RawstorOSTFrameResponse response = {
            .head{
                .magic = magic,
                .cmd = RAWSTOR_CMD_SET_OBJECT,
                .cid = cid,
            },
            .body = {
                .res = res,
                .len = 0,
                .hash = 0,
            },
        };
        _server.write(
            "RAWSTOR_CMD_SET_OBJECT >>>", &response, sizeof(response)
        );
        return;
    }

    RawstorOSTFrameHelloBody hello = {
        .version = RAWSTOR_PROTOCOL_VERSION,
        .features = 0,
    };
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = sizeof(hello),
            .hash = rawstd_hash_scalar(&hello, sizeof(hello)),
        },
    };
    iovec iov[2] = {
        {
            .iov_base = &response,
            .iov_len = sizeof(response),
        },
        {
            .iov_base = &hello,
            .iov_len = sizeof(hello),
        },
    };
    _server.writev(
        "RAWSTOR_CMD_SET_OBJECT >>>", iov, sizeof(iov) / sizeof(iov[0])
    );
}

void Session::cmd_set_object(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_set_object_request();
    cmd_set_object_response(magic, cid, res);
}

void Session::cmd_handshake() {
    cmd_set_object(RAWSTOR_MAGIC, 0, 0);
}

void Session::cmd_release_request() {
    _server.read(
        "RAWSTOR_CMD_RELEASE <<<", sizeof(RawstorOSTFrameBasic),
        [](const void*) {}
    );
}

void Session::cmd_release_response(uint32_t magic, uint16_t cid, int32_t res) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_RELEASE,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = 0,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_RELEASE >>>", &response, sizeof(response));
}

void Session::cmd_release(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_release_request();
    cmd_release_response(magic, cid, res);
}

void Session::cmd_read_request() {
    _server.read(
        "RAWSTOR_CMD_READ <<<", sizeof(RawstorOSTFrameIO), [](const void*) {}
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
            .len = static_cast<uint32_t>(size),
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

void Session::cmd_read_error(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_read_request();

    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_READ,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = 0,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_READ >>>", &response, sizeof(response));
}

void Session::cmd_write_request(size_t size) {
    _server.read(
        "RAWSTOR_CMD_WRITE <<<", sizeof(RawstorOSTFrameIO) + size,
        [](const void*) {}
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
            .len = 0,
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

void Session::cmd_spec_request() {
    _server.read(
        "RAWSTOR_CMD_SPEC <<<", sizeof(RawstorOSTFrameBasic), [](const void*) {}
    );
}

void Session::cmd_spec_response(
    uint32_t magic, uint16_t cid, int32_t res,
    const RawstorOSTFrameMetaBody& meta
) {
    if (res < 0) {
        RawstorOSTFrameResponse response = {
            .head{
                .magic = magic,
                .cmd = RAWSTOR_CMD_SPEC,
                .cid = cid,
            },
            .body = {
                .res = res,
                .len = 0,
                .hash = 0,
            },
        };
        _server.write("RAWSTOR_CMD_SPEC >>>", &response, sizeof(response));
        return;
    }

    RawstorOSTFrameSpecResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_SPEC,
            .cid = cid,
        },
        .body =
            {
                .res = res,
                .len = sizeof(meta),
                .hash = rawstd_hash_scalar(&meta, sizeof(meta)),
            },
        .meta = meta,
    };
    _server.write("RAWSTOR_CMD_SPEC >>>", &response, sizeof(response));
}

void Session::cmd_spec(
    uint32_t magic, uint16_t cid, int32_t res,
    const RawstorOSTFrameMetaBody& meta
) {
    cmd_spec_request();
    cmd_spec_response(magic, cid, res, meta);
}

void Session::cmd_set_state_request() {
    _server.read(
        "RAWSTOR_CMD_SET_STATE <<<", sizeof(RawstorOSTFrameMeta),
        [](const void*) {}
    );
}

void Session::cmd_set_state_response(
    uint32_t magic, uint16_t cid, int32_t res
) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_SET_STATE,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = 0,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_SET_STATE >>>", &response, sizeof(response));
}

void Session::cmd_set_state(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_set_state_request();
    cmd_set_state_response(magic, cid, res);
}

void Session::cmd_list_request() {
    _server.read(
        "RAWSTOR_CMD_LIST_CHUNKS <<<", sizeof(RawstorOSTFrameBasic),
        [](const void*) {}
    );
}

void Session::cmd_list_response(
    uint32_t magic, uint16_t cid, int32_t res,
    const std::vector<RawstorOSTFrameMetaBody>& records
) {
    if (res < 0 || records.empty()) {
        RawstorOSTFrameResponse response = {
            .head{
                .magic = magic,
                .cmd = RAWSTOR_CMD_LIST_CHUNKS,
                .cid = cid,
            },
            .body = {
                .res = res,
                .len = 0,
                .hash = 0,
            },
        };
        _server.write(
            "RAWSTOR_CMD_LIST_CHUNKS >>>", &response, sizeof(response)
        );
        return;
    }

    size_t len = records.size() * sizeof(RawstorOSTFrameMetaBody);
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_LIST_CHUNKS,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = static_cast<uint32_t>(len),
            .hash = rawstd_hash_scalar(records.data(), len),
        },
    };
    iovec iov[2] = {
        {
            .iov_base = &response,
            .iov_len = sizeof(response),
        },
        {
            .iov_base = const_cast<RawstorOSTFrameMetaBody*>(records.data()),
            .iov_len = len,
        },
    };
    _server.writev(
        "RAWSTOR_CMD_LIST_CHUNKS >>>", iov, sizeof(iov) / sizeof(iov[0])
    );
}

void Session::cmd_list(
    uint32_t magic, uint16_t cid, int32_t res,
    const std::vector<RawstorOSTFrameMetaBody>& records
) {
    cmd_list_request();
    cmd_list_response(magic, cid, res, records);
}

void Session::cmd_flush_request() {
    _server.read(
        "RAWSTOR_CMD_FLUSH <<<", sizeof(RawstorOSTFrameIO), [](const void*) {}
    );
}

void Session::cmd_flush_response(uint32_t magic, uint16_t cid, int32_t res) {
    RawstorOSTFrameResponse response = {
        .head{
            .magic = magic,
            .cmd = RAWSTOR_CMD_FLUSH,
            .cid = cid,
        },
        .body = {
            .res = res,
            .len = 0,
            .hash = 0,
        },
    };
    _server.write("RAWSTOR_CMD_FLUSH >>>", &response, sizeof(response));
}

void Session::cmd_flush(uint32_t magic, uint16_t cid, int32_t res) {
    cmd_flush_request();
    cmd_flush_response(magic, cid, res);
}

} // namespace tests
} // namespace rawstor
