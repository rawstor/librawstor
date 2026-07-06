#include "volume.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <utility>

#include <cerrno>
#include <cstring>

namespace {

using rawstor::mds::WireMap;
using rawstor::mds::WireSlot;

RawstdUUID target_uuid(const rawstd::URI& target) {
    RawstdUUID ret;
    int res = rawstd_uuid_from_string(&ret, target.path().filename().c_str());
    if (res < 0) {
        rawstd_error("Malformed volume target: %s\n", target.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return ret;
}

std::string target_location(const rawstd::URI& target) {
    const std::string& s = target.str();
    const std::string& path = target.path().str();
    return s.substr(0, s.size() - path.size());
}

uint64_t next_pow2(uint64_t v) {
    uint64_t ret = 1;
    while (ret < v) {
        ret <<= 1;
    }
    return ret;
}

/* The wire policy from spec fields; zeros are the documented defaults. */
RawstorVolPolicy policy_of(const RawstorObjectSpec& sp) {
    RawstorVolPolicy ret{};
    ret.redundancy = RAWSTOR_VOL_REDUNDANCY_MIRROR;
    ret.width = sp.width != 0 ? sp.width : 1;
    ret.failure_domain =
        sp.failure_domain != 0 ? sp.failure_domain : RAWSTOR_VOL_DOMAIN_SERVER;
    ret.stripe_width = sp.stripe_width;
    ret.placement_seed = 0;
    return ret;
}

std::vector<rawstd::URI> chunk_targets(const WireMap& map, uint64_t index) {
    RawstdUUID uuid = rawstor::volume_chunk_uuid(map.volume_id, index);
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstd::URI> ret;
    ret.reserve(map.chunks[index].size());
    for (const WireSlot& slot : map.chunks[index]) {
        if (slot.address.empty()) {
            /*
             * The MDS could not resolve the OST: refuse loudly instead of
             * silently opening under-protected.
             */
            rawstd_error("Chunk slot without a resolved OST address\n");
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        std::ostringstream oss;
        oss << "ost://" << slot.address << "/" << uuid_string;
        ret.emplace_back(oss.str());
    }
    return ret;
}

uint64_t
chunk_logical_size(uint64_t logical_size, uint64_t chunk_size, uint64_t index) {
    uint64_t begin = index * chunk_size;
    return std::min(chunk_size, logical_size - begin);
}

/* Sequential create/remove of every chunk object, with create rollback. */
struct ProvisionState {
    rawio::Queue& queue;
    WireMap map;
    std::shared_ptr<rawstor::mds::Client> mds;
    uint64_t next = 0;
    uint64_t created = 0;
    std::function<void(int)> cb;

    explicit ProvisionState(rawio::Queue& q) : queue(q) {}
};

void provision_next(const std::shared_ptr<ProvisionState>& st);
void provision_rollback(const std::shared_ptr<ProvisionState>& st, int error);

void provision_next(const std::shared_ptr<ProvisionState>& st) {
    if (st->next == st->map.chunks.size()) {
        st->cb(0);
        return;
    }

    RawstorObjectSpec sp{};
    sp.size =
        chunk_logical_size(st->map.logical_size, st->map.chunk_size, st->next);
    /* The placement identity the chunk carries from now on. */
    sp.member_kind = RAWSTOR_MEMBER_DATA;
    memcpy(sp.volume_id, st->map.volume_id.bytes, sizeof(sp.volume_id));
    sp.logical_index = st->next;
    sp.chunk_size = st->map.chunk_size;
    sp.snap_version = 0;
    sp.width = st->map.policy.width;
    sp.failure_domain = st->map.policy.failure_domain;
    sp.stripe_width = st->map.policy.stripe_width;

    try {
        rawstor::Object::create(
            st->queue, chunk_targets(st->map, st->next), sp, [st](int error) {
                if (error) {
                    provision_rollback(st, error);
                    return;
                }
                st->created = ++st->next;
                provision_next(st);
            }
        );
    } catch (const std::system_error& e) {
        provision_rollback(st, e.code().value());
    } catch (const std::bad_alloc&) {
        provision_rollback(st, ENOMEM);
    }
}

void provision_rollback(const std::shared_ptr<ProvisionState>& st, int error) {
    if (st->created == 0) {
        st->cb(error);
        return;
    }

    --st->created;

    try {
        rawstor::Object::remove(
            st->queue, chunk_targets(st->map, st->created),
            [st, error](int remove_error) {
                if (remove_error) {
                    rawstd_error(
                        "Failed to rollback chunk create: %s\n",
                        strerror(remove_error)
                    );
                }
                provision_rollback(st, error);
            }
        );
    } catch (const std::exception& e) {
        rawstd_error("Failed to rollback chunk create: %s\n", e.what());
        st->cb(error);
    }
}

void remove_next(const std::shared_ptr<ProvisionState>& st) {
    if (st->next == st->map.chunks.size()) {
        st->cb(0);
        return;
    }

    try {
        rawstor::Object::remove(
            st->queue, chunk_targets(st->map, st->next), [st](int error) {
                if (error && error != ENOENT) {
                    st->cb(error);
                    return;
                }
                ++st->next;
                remove_next(st);
            }
        );
    } catch (const std::system_error& e) {
        st->cb(e.code().value());
    } catch (const std::bad_alloc&) {
        st->cb(ENOMEM);
    }
}

} // namespace

namespace rawstor {

std::vector<VolumeSegment>
volume_segments(off_t offset, size_t size, uint64_t chunk_size) {
    std::vector<VolumeSegment> ret;

    uint64_t at = static_cast<uint64_t>(offset);
    size_t left = size;
    size_t buf_offset = 0;

    while (left > 0) {
        uint64_t index = at / chunk_size;
        uint64_t chunk_offset = at % chunk_size;
        size_t take = static_cast<size_t>(
            std::min<uint64_t>(left, chunk_size - chunk_offset)
        );

        ret.push_back(
            VolumeSegment{
                static_cast<uint32_t>(index),
                static_cast<off_t>(chunk_offset),
                take,
                buf_offset,
            }
        );

        at += take;
        buf_offset += take;
        left -= take;
    }

    return ret;
}

RawstdUUID volume_chunk_uuid(const RawstdUUID& volume_id, uint64_t index) {
    RawstdUUID ret = volume_id;
    for (unsigned i = 0; i < 8; ++i) {
        ret.bytes[8 + i] ^= static_cast<uint8_t>(index >> (8 * i));
    }
    return ret;
}

Volume::Volume(
    rawio::Queue& queue, const RawstdUUID& id, std::string location,
    const WireMap& map
) :
    _queue(queue),
    _id(id),
    _location(std::move(location)),
    _size(map.logical_size),
    _chunk_size(map.chunk_size),
    _map_epoch(map.map_epoch) {
    _chunks.resize(map.chunks.size());
    for (size_t i = 0; i < map.chunks.size(); ++i) {
        _chunks[i].targets = chunk_targets(map, i);
    }
}

Volume::~Volume() {
    for (Chunk& chunk : _chunks) {
        delete chunk.object;
        chunk.object = nullptr;
    }
}

void Volume::open(
    rawio::Queue& queue, const rawstd::URI& target,
    std::function<void(Volume*, int)>&& cb
) {
    RawstdUUID id = target_uuid(target);
    std::string location = target_location(target);

    auto client = std::make_shared<mds::Client>(queue, rawstd::URI(location));

    client->connect([&queue, id, location, client,
                     cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(nullptr, error);
            return;
        }

        client->vol_open(
            id, 0,
            [&queue, id, location = std::move(location), client,
             cb = std::move(cb)](WireMap&& map, int error) {
                if (error) {
                    cb(nullptr, error);
                    return;
                }

                try {
                    /* The client closes with the shared_ptr. */
                    cb(new Volume(queue, id, location, map), 0);
                } catch (const std::system_error& e) {
                    cb(nullptr, e.code().value());
                } catch (const std::bad_alloc&) {
                    cb(nullptr, ENOMEM);
                }
            }
        );
    });
}

void Volume::create(
    rawio::Queue& queue, const rawstd::URI& target, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    RawstdUUID id = target_uuid(target);
    std::string location = target_location(target);

    if (sp.size == 0) {
        cb(EINVAL);
        return;
    }

    uint64_t chunk_size =
        sp.chunk_size != 0 ? sp.chunk_size : next_pow2(sp.size);
    RawstorVolPolicy policy = policy_of(sp);

    auto client = std::make_shared<mds::Client>(queue, rawstd::URI(location));

    client->connect([&queue, id, size = sp.size, chunk_size, policy, client,
                     cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        client->vol_create(
            id, size, chunk_size, policy,
            [&queue, id, client, cb = std::move(cb)](int error) mutable {
                if (error) {
                    cb(error);
                    return;
                }

                /* Materialize every chunk object on its OSTs. */
                client->vol_open(
                    id, 0,
                    [&queue, id, client,
                     cb = std::move(cb)](WireMap&& map, int error) mutable {
                        if (error) {
                            cb(error);
                            return;
                        }

                        auto st = std::make_shared<ProvisionState>(queue);
                        st->map = std::move(map);
                        st->mds = client;
                        st->cb = [id, client,
                                  cb = std::move(cb)](int error) mutable {
                            if (!error) {
                                cb(0);
                                return;
                            }
                            /* Provisioning failed: drop the map too. */
                            client->vol_remove(
                                id, [error, client,
                                     cb = std::move(cb)](int remove_error) {
                                    if (remove_error) {
                                        rawstd_error(
                                            "Failed to rollback volume: %s\n",
                                            strerror(remove_error)
                                        );
                                    }
                                    cb(error);
                                }
                            );
                        };
                        provision_next(st);
                    }
                );
            }
        );
    });
}

void Volume::remove(
    rawio::Queue& queue, const rawstd::URI& target,
    std::function<void(int)>&& cb
) {
    RawstdUUID id = target_uuid(target);
    std::string location = target_location(target);

    auto client = std::make_shared<mds::Client>(queue, rawstd::URI(location));

    client->connect([&queue, id, client,
                     cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        client->vol_open(
            id, 0,
            [&queue, id, client,
             cb = std::move(cb)](WireMap&& map, int error) mutable {
                if (error) {
                    cb(error);
                    return;
                }

                auto st = std::make_shared<ProvisionState>(queue);
                st->map = std::move(map);
                st->mds = client;
                st->cb = [id, client, cb = std::move(cb)](int error) mutable {
                    if (error) {
                        cb(error);
                        return;
                    }
                    client->vol_remove(
                        id,
                        [client, cb = std::move(cb)](int error) { cb(error); }
                    );
                };
                remove_next(st);
            }
        );
    });
}

void Volume::spec(
    rawio::Queue& queue, const rawstd::URI& target, RawstorObjectSpec* sp,
    std::function<void(int)>&& cb
) {
    RawstdUUID id = target_uuid(target);
    std::string location = target_location(target);

    auto client = std::make_shared<mds::Client>(queue, rawstd::URI(location));

    client->connect([id, sp, client, cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        client->vol_open(
            id, 0, [sp, client, cb = std::move(cb)](WireMap&& map, int error) {
                if (!error) {
                    *sp = RawstorObjectSpec{};
                    sp->size = map.logical_size;
                    sp->chunk_size = map.chunk_size;
                    sp->width = map.policy.width;
                    sp->failure_domain = map.policy.failure_domain;
                    sp->stripe_width = map.policy.stripe_width;
                }
                cb(error);
            }
        );
    });
}

std::vector<rawstd::URI> Volume::locations() const {
    return {rawstd::URI(_location)};
}

void Volume::_with_chunk(
    uint32_t index, std::function<void(Object*, int)>&& cb
) {
    Chunk& chunk = _chunks[index];

    if (chunk.object != nullptr) {
        cb(chunk.object, 0);
        return;
    }

    chunk.waiters.push_back(std::move(cb));

    if (chunk.opening) {
        return;
    }
    chunk.opening = true;

    Object::open(
        _queue, chunk.targets, [this, index](Object* object, int error) {
            Chunk& chunk = _chunks[index];
            chunk.opening = false;
            if (!error) {
                chunk.object = object;
            }

            std::vector<std::function<void(Object*, int)>> waiters;
            waiters.swap(chunk.waiters);
            for (auto& waiter : waiters) {
                waiter(object, error);
            }
        }
    );
}

/*
 * Common scalar I/O fan-out: every segment goes to its chunk object,
 * results are summed, the first error wins (result 0).
 */
void Volume::_rw_segments(
    std::shared_ptr<std::vector<VolumeSegment>> segments, bool write, void* buf,
    std::function<void(size_t, int)>&& cb
) {
    struct Fan {
        size_t pending;
        size_t result = 0;
        int error = 0;
        std::function<void(size_t, int)> cb;
    };

    auto fan = std::make_shared<Fan>();
    fan->pending = segments->size();
    fan->cb = std::move(cb);

    for (const VolumeSegment& segment : *segments) {
        auto done = [fan](size_t result, int error) {
            if (error && fan->error == 0) {
                fan->error = error;
            }
            fan->result += result;
            if (--fan->pending == 0) {
                fan->cb(fan->error ? 0 : fan->result, fan->error);
            }
        };

        _with_chunk(
            segment.index,
            [segment, write, buf, done](Object* object, int error) mutable {
                if (error) {
                    done(0, error);
                    return;
                }

                char* at = static_cast<char*>(buf) + segment.buf_offset;
                if (write) {
                    object->pwrite(
                        at, segment.size, segment.chunk_offset, std::move(done)
                    );
                } else {
                    object->pread(
                        at, segment.size, segment.chunk_offset, std::move(done)
                    );
                }
            }
        );
    }
}

void Volume::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        cb(0, EINVAL);
        return;
    }

    auto segments = std::make_shared<std::vector<VolumeSegment>>(
        volume_segments(offset, size, _chunk_size)
    );
    _rw_segments(segments, false, buf, std::move(cb));
}

void Volume::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        cb(0, EINVAL);
        return;
    }

    auto segments = std::make_shared<std::vector<VolumeSegment>>(
        volume_segments(offset, size, _chunk_size)
    );
    _rw_segments(segments, true, const_cast<void*>(buf), std::move(cb));
}

void Volume::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        cb(0, EINVAL);
        return;
    }

    auto segments = std::make_shared<std::vector<VolumeSegment>>(
        volume_segments(offset, size, _chunk_size)
    );

    if (segments->size() == 1) {
        const VolumeSegment& segment = segments->front();
        _with_chunk(
            segment.index,
            [iov, niov, size, segment,
             cb = std::move(cb)](Object* object, int error) mutable {
                if (error) {
                    cb(0, error);
                    return;
                }
                object->preadv(
                    iov, niov, size, segment.chunk_offset, std::move(cb)
                );
            }
        );
        return;
    }

    /* Cross-chunk vectored I/O bounces through a flat buffer (rare). */
    auto bounce = std::make_shared<std::vector<char>>(size);
    _rw_segments(
        segments, false, bounce->data(),
        [iov, niov, size, bounce,
         cb = std::move(cb)](size_t result, int error) {
            if (!error) {
                iovec src = {bounce->data(), size};
                rawstd_iovec_to_iovec(&src, 1, 0, iov, niov);
            }
            cb(result, error);
        }
    );
}

void Volume::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        cb(0, EINVAL);
        return;
    }

    auto segments = std::make_shared<std::vector<VolumeSegment>>(
        volume_segments(offset, size, _chunk_size)
    );

    if (segments->size() == 1) {
        const VolumeSegment& segment = segments->front();
        _with_chunk(
            segment.index,
            [iov, niov, size, segment,
             cb = std::move(cb)](Object* object, int error) mutable {
                if (error) {
                    cb(0, error);
                    return;
                }
                object->pwritev(
                    iov, niov, size, segment.chunk_offset, std::move(cb)
                );
            }
        );
        return;
    }

    auto bounce = std::make_shared<std::vector<char>>(size);
    rawstd_iovec_to_buf(iov, niov, 0, bounce->data(), size);
    _rw_segments(
        segments, true, bounce->data(),
        [bounce, cb = std::move(cb)](size_t result, int error) {
            cb(result, error);
        }
    );
}

void Volume::flush(std::function<void(size_t, int)>&& cb) {
    struct Fan {
        size_t pending = 0;
        int error = 0;
        std::function<void(size_t, int)> cb;
    };

    auto fan = std::make_shared<Fan>();
    fan->cb = std::move(cb);

    for (Chunk& chunk : _chunks) {
        if (chunk.object != nullptr) {
            ++fan->pending;
        }
    }

    if (fan->pending == 0) {
        fan->cb(0, 0);
        return;
    }

    for (Chunk& chunk : _chunks) {
        if (chunk.object == nullptr) {
            continue;
        }
        chunk.object->flush([fan](size_t, int error) {
            if (error && fan->error == 0) {
                fan->error = error;
            }
            if (--fan->pending == 0) {
                fan->cb(0, fan->error);
            }
        });
    }
}

void Volume::_close_next(
    size_t index, int first_error, std::function<void(int)>&& cb
) {
    while (index < _chunks.size() && _chunks[index].object == nullptr) {
        ++index;
    }

    if (index == _chunks.size()) {
        delete this;
        cb(first_error);
        return;
    }

    Object* object = _chunks[index].object;
    _chunks[index].object = nullptr;

    /* Object::close destroys the object regardless of the outcome. */
    object->close([this, index, first_error,
                   cb = std::move(cb)](int error) mutable {
        _close_next(
            index + 1, first_error != 0 ? first_error : error, std::move(cb)
        );
    });
}

void Volume::close(std::function<void(int)>&& cb) {
    _close_next(0, 0, std::move(cb));
}

} // namespace rawstor
