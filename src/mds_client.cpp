#include "mds_client.hpp"

#include "opts.h"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>

#include <rawstor/protocol.h>

#include <arpa/inet.h>

#include <unistd.h>

#include <memory>
#include <utility>

#include <cerrno>
#include <cstring>

namespace {

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EPROTO;
}

} // namespace

namespace rawstor {
namespace mds {

Client::Client(rawio::Queue& queue, const rawstd::URI& location) :
    _queue(queue),
    _location(location),
    _fd(-1),
    _cid_counter(0) {
}

Client::~Client() {
    if (_fd != -1) {
        ::close(_fd);
        rawstd_info("fd %d: Closed\n", _fd);
    }
}

void Client::connect(std::function<void(int)>&& cb) {
    int res;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            res = rawstd_socket_set_snd_timeout(fd, so_sndtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            res = rawstd_socket_set_rcv_timeout(fd, so_rcvtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        auto servaddr = std::make_shared<sockaddr_in>();
        servaddr->sin_family = AF_INET;
        servaddr->sin_port = htons(_location.port());

        res = inet_pton(
            AF_INET, _location.hostname().c_str(), &servaddr->sin_addr
        );
        if (res == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        rawstd_info(
            "fd %d: Connecting to %s...\n", fd, _location.str().c_str()
        );

        _queue.connect(
            fd, reinterpret_cast<const sockaddr*>(servaddr.get()),
            sizeof(*servaddr),
            [this, fd, servaddr, cb = std::move(cb)](int result) mutable {
                if (result < 0) {
                    ::close(fd);
                    cb(-result);
                    return;
                }

                try {
                    rawio::Queue::setup_fd(fd);
                } catch (const std::system_error& e) {
                    ::close(fd);
                    cb(e.code().value());
                    return;
                }

                _fd = fd;

                /* The handshake: SET_OBJECT with a null binding. */
                auto request = std::make_shared<RawstorOSTFrameSetObject>(
                    (RawstorOSTFrameSetObject){
                        .head =
                            {
                                .magic = RAWSTOR_MAGIC,
                                .cmd = RAWSTOR_CMD_SET_OBJECT,
                                .cid = _cid_counter++,
                            },
                        .body = {
                            .version = RAWSTOR_PROTOCOL_VERSION,
                            .features = 0,
                            .obj_id = {},
                            .val = 0,
                        },
                    }
                );

                try {
                    _exchange(
                        request.get(), sizeof(*request), RAWSTOR_CMD_SET_OBJECT,
                        [request, cb = std::move(cb)](
                            std::vector<unsigned char>&& payload, int error
                        ) {
                            if (!error &&
                                payload.size() !=
                                    sizeof(RawstorOSTFrameHelloBody)) {
                                error = EPROTO;
                            }

                            RawstorOSTFrameHelloBody hello{};
                            if (!error) {
                                memcpy(&hello, payload.data(), sizeof(hello));
                                if (hello.version != RAWSTOR_PROTOCOL_VERSION) {
                                    rawstd_error(
                                        "Unsupported server protocol "
                                        "version: %u != %u\n",
                                        hello.version, RAWSTOR_PROTOCOL_VERSION
                                    );
                                    error = EPROTONOSUPPORT;
                                }
                            }

                            cb(error);
                        }
                    );
                } catch (const std::system_error& e) {
                    cb(e.code().value());
                }
            }
        );
    } catch (...) {
        ::close(fd);
        throw;
    }
}

/*
 * One request/response exchange: writes the request, reads the response
 * frame, then the announced payload. The payload hash is verified. A
 * server error (res < 0) is delivered as a positive errno with an empty
 * payload.
 */
void Client::_exchange(
    const void* request, size_t size, RawstorOSTCommandType cmd,
    std::function<void(std::vector<unsigned char>&&, int)>&& cb
) {
    auto cb_sp = std::make_shared<
        std::function<void(std::vector<unsigned char>&&, int)>>(std::move(cb));

    auto fail = [cb_sp](int error) { (*cb_sp)({}, error); };

    _queue.write(
        _fd, request, size,
        [this, q = &_queue, fd = _fd, size, cmd, cb_sp,
         fail](size_t result, int error) {
            if (!error) {
                error = validate_result(fd, size, result);
            }

            if (error) {
                fail(error);
                return;
            }

            auto response = std::make_shared<RawstorOSTFrameResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(*response),
                    [q, fd, cmd, response, cb_sp,
                     fail](size_t result, int error) {
                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error && response->head.magic != RAWSTOR_MAGIC) {
                            rawstd_error("fd %d: Bad magic\n", fd);
                            error = EPROTO;
                        }

                        if (!error && response->head.cmd != cmd) {
                            rawstd_error(
                                "fd %d: Unexpected command: %d\n", fd,
                                response->head.cmd
                            );
                            error = EPROTO;
                        }

                        if (error) {
                            fail(error);
                            return;
                        }

                        if (response->body.res < 0) {
                            if (response->body.len != 0) {
                                fail(EPROTO);
                                return;
                            }
                            fail(-response->body.res);
                            return;
                        }

                        if (response->body.len == 0) {
                            (*cb_sp)({}, 0);
                            return;
                        }

                        /* A copy: a packed field cannot bind to a ref. */
                        uint32_t len = response->body.len;
                        auto payload =
                            std::make_shared<std::vector<unsigned char>>(len);

                        try {
                            q->read(
                                fd, payload->data(), payload->size(),
                                [fd, response, payload,
                                 cb_sp](size_t result, int error) {
                                    if (!error) {
                                        error = validate_result(
                                            fd, payload->size(), result
                                        );
                                    }

                                    if (!error &&
                                        rawstd_hash_scalar(
                                            payload->data(), payload->size()
                                        ) != response->body.hash) {
                                        rawstd_error(
                                            "fd %d: Payload hash mismatch\n", fd
                                        );
                                        error = EPROTO;
                                    }

                                    if (error) {
                                        (*cb_sp)({}, error);
                                        return;
                                    }

                                    (*cb_sp)(std::move(*payload), 0);
                                }
                            );
                        } catch (const std::system_error& e) {
                            fail(e.code().value());
                        } catch (const std::bad_alloc&) {
                            fail(ENOMEM);
                        }
                    }
                );
            } catch (const std::system_error& e) {
                fail(e.code().value());
            } catch (const std::bad_alloc&) {
                fail(ENOMEM);
            }
        }
    );
}

void Client::vol_create(
    const RawstdUUID& volume_id, uint64_t logical_size, uint64_t chunk_size,
    const RawstorVolPolicy& policy, std::function<void(int)>&& cb
) {
    auto request = std::make_shared<RawstorVolCreate>((RawstorVolCreate){
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_VOL_CREATE,
                .cid = _cid_counter++,
            },
        .body = {
            .volume_id = {},
            .logical_size = logical_size,
            .chunk_size = chunk_size,
            .policy = policy,
        },
    });
    memcpy(
        request->body.volume_id, volume_id.bytes,
        sizeof(request->body.volume_id)
    );

    _exchange(
        request.get(), sizeof(*request), RAWSTOR_CMD_VOL_CREATE,
        [request,
         cb = std::move(cb)](std::vector<unsigned char>&& payload, int error) {
            if (!error && payload.size() != sizeof(RawstorVolCreatedBody)) {
                error = EPROTO;
            }
            cb(error);
        }
    );
}

void Client::vol_open(
    const RawstdUUID& volume_id, uint64_t snap_id,
    std::function<void(WireMap&&, int)>&& cb
) {
    auto request =
        std::make_shared<RawstorOSTFrameBasic>((RawstorOSTFrameBasic){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_VOL_OPEN,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = snap_id,
            },
        });
    memcpy(request->body.obj_id, volume_id.bytes, sizeof(request->body.obj_id));

    _exchange(
        request.get(), sizeof(*request), RAWSTOR_CMD_VOL_OPEN,
        [request,
         cb = std::move(cb)](std::vector<unsigned char>&& payload, int error) {
            if (error) {
                cb({}, error);
                return;
            }

            WireMap map{};
            size_t off = 0;

            auto take = [&payload, &off](void* out, size_t size) -> bool {
                if (payload.size() - off < size) {
                    return false;
                }
                memcpy(out, payload.data() + off, size);
                off += size;
                return true;
            };

            RawstorVolDescriptorBody descriptor{};
            if (!take(&descriptor, sizeof(descriptor))) {
                cb({}, EPROTO);
                return;
            }

            memcpy(
                map.volume_id.bytes, descriptor.volume_id,
                sizeof(map.volume_id.bytes)
            );
            map.logical_size = descriptor.logical_size;
            map.chunk_size = descriptor.chunk_size;
            map.policy = descriptor.policy;
            map.map_epoch = descriptor.map_epoch;
            map.chunks.resize(descriptor.nchunks);

            for (uint32_t i = 0; i < descriptor.nchunks; ++i) {
                RawstorVolChunkEntry entry{};
                if (!take(&entry, sizeof(entry))) {
                    cb({}, EPROTO);
                    return;
                }

                map.chunks[i].reserve(entry.width);
                for (unsigned s = 0; s < entry.width; ++s) {
                    RawstorVolChunkSlot slot{};
                    if (!take(&slot, sizeof(slot))) {
                        cb({}, EPROTO);
                        return;
                    }

                    WireSlot out{};
                    out.slot_index = slot.slot_index;
                    memcpy(
                        out.ost_id.bytes, slot.ost_id, sizeof(out.ost_id.bytes)
                    );
                    slot.address[sizeof(slot.address) - 1] = '\0';
                    out.address = slot.address;
                    map.chunks[i].push_back(std::move(out));
                }
            }

            if (off != payload.size()) {
                cb({}, EPROTO);
                return;
            }

            cb(std::move(map), 0);
        }
    );
}

void Client::vol_resize(
    const RawstdUUID& volume_id, uint64_t new_size,
    std::function<void(uint64_t, int)>&& cb
) {
    auto request =
        std::make_shared<RawstorOSTFrameBasic>((RawstorOSTFrameBasic){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_VOL_RESIZE,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = new_size,
            },
        });
    memcpy(request->body.obj_id, volume_id.bytes, sizeof(request->body.obj_id));

    _exchange(
        request.get(), sizeof(*request), RAWSTOR_CMD_VOL_RESIZE,
        [request,
         cb = std::move(cb)](std::vector<unsigned char>&& payload, int error) {
            RawstorVolResizedBody resized{};
            if (!error && payload.size() != sizeof(resized)) {
                error = EPROTO;
            }
            if (!error) {
                memcpy(&resized, payload.data(), sizeof(resized));
            }
            cb(resized.map_epoch, error);
        }
    );
}

void Client::vol_remove(
    const RawstdUUID& volume_id, std::function<void(int)>&& cb
) {
    auto request =
        std::make_shared<RawstorOSTFrameBasic>((RawstorOSTFrameBasic){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_VOL_REMOVE,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = 0,
            },
        });
    memcpy(request->body.obj_id, volume_id.bytes, sizeof(request->body.obj_id));

    _exchange(
        request.get(), sizeof(*request), RAWSTOR_CMD_VOL_REMOVE,
        [request, cb = std::move(cb)](std::vector<unsigned char>&&, int error) {
            cb(error);
        }
    );
}

} // namespace mds
} // namespace rawstor
