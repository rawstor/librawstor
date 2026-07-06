#include "session.hpp"

#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <functional>
#include <memory>
#include <system_error>
#include <vector>

#include <cerrno>
#include <cstring>

namespace {

typedef std::function<void(size_t, int)> IOCallback;

int io_callback(size_t result, int error, void* data) {
    std::unique_ptr<IOCallback> cb(static_cast<IOCallback*>(data));

    try {
        (*cb)(result, error);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EIO;
}

void send_response(
    RawIOQueue* queue, int fd, const RawstorOSTCommandType& type, uint16_t cid,
    int32_t result,
    const std::shared_ptr<std::vector<unsigned char>>& payload = nullptr
) {
    auto response = std::make_shared<RawstorOSTFrameResponse>((
        RawstorOSTFrameResponse
    ){
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = type,
                .cid = cid,
            },
        .body = {
            .res = result,
            .len =
                payload != nullptr ? static_cast<uint32_t>(payload->size()) : 0,
            .hash = payload != nullptr
                        ? rawstd_hash_scalar(payload->data(), payload->size())
                        : 0,
        },
    });

    size_t total = sizeof(*response) + response->body.len;

    auto iov = std::make_shared<std::vector<iovec>>();
    iov->push_back({
        .iov_base = response.get(),
        .iov_len = sizeof(*response),
    });
    if (payload != nullptr) {
        iov->push_back({
            .iov_base = payload->data(),
            .iov_len = payload->size(),
        });
    }

    auto cb = std::make_unique<IOCallback>([fd, total, response, payload,
                                            iov](size_t result, int error) {
        if (!error) {
            error = validate_result(fd, total, result);
        }

        if (error) {
            rawstd_error("%s\n", strerror(error));
        }
    });

    int res = rawio_writev(
        queue, fd, iov->data(), iov->size(), io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

std::shared_ptr<std::vector<unsigned char>> make_hello() {
    RawstorOSTFrameHelloBody hello{
        .version = RAWSTOR_PROTOCOL_VERSION,
        .features = 0,
    };

    auto ret = std::make_shared<std::vector<unsigned char>>(sizeof(hello));
    memcpy(ret->data(), &hello, sizeof(hello));
    return ret;
}

bool uuid_is_null(const uint8_t (&id)[16]) {
    for (uint8_t byte : id) {
        if (byte != 0) {
            return false;
        }
    }
    return true;
}

int error_of(const std::system_error& e) noexcept {
    return e.code().value() > 0 ? e.code().value() : EIO;
}

} // namespace

namespace rawstor {
namespace mdsbackend {

Session::Session(RawIOQueue* queue, Server& server, int fd) :
    _queue(queue),
    _server(server),
    _fd(fd),
    _recv_event(nullptr),
    _next(&Session::_recv_head),
    _handshaken(false),
    _alive(std::make_shared<int>(0)) {
    int res = rawio_recv_multishot(
        _queue, _fd, 1u << 17, 64 * 4, sizeof(_request_head), 0, _recv, this,
        &_recv_event
    );
    if (res < 0) {
        close(_fd);
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

Session::~Session() noexcept {
    if (_recv_event != nullptr) {
        int res = rawio_cancel(_queue, _recv_event);
        if (res < 0) {
            rawstd_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }
    close(_fd);
}

ssize_t Session::_recv(
    const iovec* iov, unsigned int niov, size_t result, int error, void* data
) noexcept {
    if (error == ECANCELED) {
        return 0;
    }
    Session* session = static_cast<Session*>(data);
    try {
        return session->_recv(iov, niov, result, error);
    } catch (const std::system_error& e) {
        if (e.code().value() != EPIPE) {
            rawstd_error("%s\n", e.what());
        }
        session->_server.del_session(session->_fd);
        return 0;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        session->_server.del_session(session->_fd);
        return 0;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        session->_server.del_session(session->_fd);
        return 0;
    }
}

ssize_t
Session::_recv(const iovec* iov, unsigned int niov, size_t result, int error) {
    if (error) {
        _recv_event = nullptr;
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    return (this->*_next)(iov, niov, result);
}

ssize_t
Session::_recv_head(const iovec* iov, unsigned int niov, size_t result) {
    if (result != sizeof(_request_head)) {
        rawstd_error(
            "fd %d: Unexpected request head size: %zu != %zu\n", _fd, result,
            sizeof(_request_head)
        );

        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    rawstd_iovec_to_buf(iov, niov, 0, &_request_head, sizeof(_request_head));

    if (_request_head.magic != RAWSTOR_MAGIC) {
        rawstd_error(
            "fd %d: Unexpected magic number: %x != %x\n", _fd,
            _request_head.magic, RAWSTOR_MAGIC
        );

        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    _next = &Session::_recv_body;

    switch (_request_head.cmd) {
    case RAWSTOR_CMD_SET_OBJECT:
        return sizeof(RawstorOSTFrameSetObjectBody);
    case RAWSTOR_CMD_VOL_CREATE:
        return sizeof(RawstorVolCreateBody);
    case RAWSTOR_CMD_VOL_OPEN:
    case RAWSTOR_CMD_VOL_RESIZE:
    case RAWSTOR_CMD_VOL_REMOVE:
        return sizeof(RawstorOSTFrameBasicBody);
    }

    /*
     * Any opcode outside the MDS role — data commands, the witness subset
     * until stage 3, or garbage — answers -ENOSYS. The body length may be
     * unknown, so the stream position is lost: consume and ignore
     * everything until the deferred close lands.
     */
    rawstd_error(
        "fd %d: Command outside the MDS role: %u\n", _fd, _request_head.cmd
    );
    _close_after_response(_request_head, -ENOSYS);
    _next = &Session::_recv_ignore;

    return sizeof(RawstorOSTFrameHead);
}

ssize_t Session::_recv_ignore(const iovec*, unsigned int, size_t) {
    _next = &Session::_recv_ignore;

    return sizeof(RawstorOSTFrameHead);
}

ssize_t
Session::_recv_body(const iovec* iov, unsigned int niov, size_t result) {
    _next = &Session::_recv_head;

    /* SET_OBJECT is the handshake and must be the first command. */
    if (!_handshaken && _request_head.cmd != RAWSTOR_CMD_SET_OBJECT) {
        rawstd_error(
            "fd %d: Command %u before the SET_OBJECT handshake\n", _fd,
            _request_head.cmd
        );

        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    switch (_request_head.cmd) {
    case RAWSTOR_CMD_SET_OBJECT:
        if (result != sizeof(_request_body.setobj)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.setobj)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.setobj, sizeof(_request_body.setobj)
        );

        _set_object(_request_head, _request_body.setobj);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_VOL_CREATE:
        if (result != sizeof(_request_body.vol_create)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.vol_create)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.vol_create,
            sizeof(_request_body.vol_create)
        );

        _vol_create(_request_head, _request_body.vol_create);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_VOL_OPEN:
    case RAWSTOR_CMD_VOL_RESIZE:
    case RAWSTOR_CMD_VOL_REMOVE:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        if (_request_head.cmd == RAWSTOR_CMD_VOL_OPEN) {
            _vol_open(_request_head, _request_body.basic);
        } else if (_request_head.cmd == RAWSTOR_CMD_VOL_RESIZE) {
            _vol_resize(_request_head, _request_body.basic);
        } else {
            _vol_remove(_request_head, _request_body.basic);
        }

        return sizeof(RawstorOSTFrameHead);
    }

    rawstd_error("fd %d: Unexpected command: %u\n", _fd, _request_head.cmd);
    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
}

void Session::_set_object(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameSetObjectBody& body
) {
    if (body.version != RAWSTOR_PROTOCOL_VERSION) {
        rawstd_error(
            "fd %d: Unsupported protocol version: %u != %u\n", _fd,
            body.version, RAWSTOR_PROTOCOL_VERSION
        );
        _close_after_response(head, -EPROTONOSUPPORT);
        return;
    }

    /* The MDS serves no objects: only control connections bind here. */
    if (!uuid_is_null(body.obj_id)) {
        rawstd_error("fd %d: Object binding on an MDS connection\n", _fd);
        send_response(_queue, _fd, RAWSTOR_CMD_SET_OBJECT, head.cid, -ENOSYS);
        return;
    }

    _handshaken = true;

    send_response(
        _queue, _fd, RAWSTOR_CMD_SET_OBJECT, head.cid, 0, make_hello()
    );
}

void Session::_vol_create(
    const RawstorOSTFrameHead& head, const RawstorVolCreateBody& body
) {
    if (body.policy.redundancy != RAWSTOR_VOL_REDUNDANCY_MIRROR ||
        body.policy.width == 0 ||
        body.policy.failure_domain > RAWSTOR_VOL_DOMAIN_OST) {
        send_response(_queue, _fd, RAWSTOR_CMD_VOL_CREATE, head.cid, -EINVAL);
        return;
    }

    mds::PlacementPolicy policy{};
    policy.width = body.policy.width;
    policy.failure_domain = static_cast<mds::Level>(body.policy.failure_domain);
    policy.stripe_width = body.policy.stripe_width;
    policy.seed = body.policy.placement_seed;

    RawstdUUID volume_id;
    memcpy(volume_id.bytes, body.volume_id, sizeof(volume_id.bytes));

    try {
        mds::VolumeDescriptor descriptor = _server.store().create(
            volume_id, body.logical_size, body.chunk_size, policy
        );

        RawstorVolCreatedBody created{};
        created.map_epoch = descriptor.map_epoch;

        auto payload =
            std::make_shared<std::vector<unsigned char>>(sizeof(created));
        memcpy(payload->data(), &created, sizeof(created));

        send_response(
            _queue, _fd, RAWSTOR_CMD_VOL_CREATE, head.cid, 0, payload
        );
    } catch (const std::system_error& e) {
        send_response(
            _queue, _fd, RAWSTOR_CMD_VOL_CREATE, head.cid, -error_of(e)
        );
    }
}

void Session::_vol_open(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID volume_id;
    memcpy(volume_id.bytes, body.obj_id, sizeof(volume_id.bytes));

    try {
        mds::VolumeMap map = _server.store().open(volume_id, body.val);

        RawstorVolDescriptorBody descriptor{};
        memcpy(
            descriptor.volume_id, map.descriptor.volume_id.bytes,
            sizeof(descriptor.volume_id)
        );
        descriptor.logical_size = map.descriptor.logical_size;
        descriptor.chunk_size = map.descriptor.chunk_size;
        descriptor.policy.redundancy = RAWSTOR_VOL_REDUNDANCY_MIRROR;
        descriptor.policy.width =
            static_cast<uint8_t>(map.descriptor.policy.width);
        descriptor.policy.failure_domain =
            static_cast<uint8_t>(map.descriptor.policy.failure_domain);
        descriptor.policy.stripe_width = map.descriptor.policy.stripe_width;
        descriptor.policy.placement_seed = map.descriptor.policy.seed;
        descriptor.map_epoch = map.descriptor.map_epoch;
        descriptor.nchunks = static_cast<uint32_t>(map.chunks.size());

        auto payload = std::make_shared<std::vector<unsigned char>>();
        payload->reserve(
            sizeof(descriptor) +
            map.chunks.size() *
                (sizeof(RawstorVolChunkEntry) +
                 map.descriptor.policy.width * sizeof(RawstorVolChunkSlot))
        );

        auto append = [&payload](const void* data, size_t size) {
            const unsigned char* bytes =
                static_cast<const unsigned char*>(data);
            payload->insert(payload->end(), bytes, bytes + size);
        };

        append(&descriptor, sizeof(descriptor));

        for (const std::vector<mds::PlacementSlot>& slots : map.chunks) {
            RawstorVolChunkEntry entry{};
            entry.version = 0;
            entry.width = static_cast<uint8_t>(slots.size());
            append(&entry, sizeof(entry));

            for (const mds::PlacementSlot& slot : slots) {
                RawstorVolChunkSlot wire{};
                wire.slot_index = slot.slot_index;
                memcpy(wire.ost_id, slot.ost_id.bytes, sizeof(wire.ost_id));

                /* ost_id -> address, resolved from the topology. */
                for (const mds::TopologyOST& ost :
                     _server.store().topology().osts()) {
                    if (memcmp(
                            ost.id.bytes, slot.ost_id.bytes,
                            sizeof(ost.id.bytes)
                        ) == 0) {
                        strncpy(
                            wire.address, ost.address.c_str(),
                            sizeof(wire.address) - 1
                        );
                        break;
                    }
                }

                append(&wire, sizeof(wire));
            }
        }

        send_response(_queue, _fd, RAWSTOR_CMD_VOL_OPEN, head.cid, 0, payload);
    } catch (const std::system_error& e) {
        send_response(
            _queue, _fd, RAWSTOR_CMD_VOL_OPEN, head.cid, -error_of(e)
        );
    }
}

void Session::_vol_resize(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID volume_id;
    memcpy(volume_id.bytes, body.obj_id, sizeof(volume_id.bytes));

    try {
        RawstorVolResizedBody resized{};
        resized.map_epoch = _server.store().resize(volume_id, body.val);

        auto payload =
            std::make_shared<std::vector<unsigned char>>(sizeof(resized));
        memcpy(payload->data(), &resized, sizeof(resized));

        send_response(
            _queue, _fd, RAWSTOR_CMD_VOL_RESIZE, head.cid, 0, payload
        );
    } catch (const std::system_error& e) {
        send_response(
            _queue, _fd, RAWSTOR_CMD_VOL_RESIZE, head.cid, -error_of(e)
        );
    }
}

void Session::_vol_remove(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID volume_id;
    memcpy(volume_id.bytes, body.obj_id, sizeof(volume_id.bytes));

    try {
        _server.store().remove(volume_id);
        send_response(_queue, _fd, RAWSTOR_CMD_VOL_REMOVE, head.cid, 0);
    } catch (const std::system_error& e) {
        send_response(
            _queue, _fd, RAWSTOR_CMD_VOL_REMOVE, head.cid, -error_of(e)
        );
    }
}

void Session::_close_after_response(
    const RawstorOSTFrameHead& head, int32_t res
) {
    auto response =
        std::make_shared<RawstorOSTFrameResponse>((RawstorOSTFrameResponse){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = head.cmd,
                    .cid = head.cid,
                },
            .body = {
                .res = res,
                .len = 0,
                .hash = 0,
            },
        });

    auto cb = std::make_unique<IOCallback>([server = &_server, fd = _fd,
                                            alive = std::weak_ptr<int>(_alive),
                                            response](size_t, int) {
        if (alive.expired()) {
            return;
        }
        server->del_session(fd);
    });

    int res_write = rawio_write(
        _queue, _fd, response.get(), sizeof(*response), io_callback, cb.get()
    );
    if (res_write < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res_write);
    }

    cb.release();
}

} // namespace mdsbackend
} // namespace rawstor
