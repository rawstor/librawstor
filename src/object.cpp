#include "object.hpp"

#include "chunk.hpp"
#include "target.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>

#include <algorithm>
#include <system_error>
#include <utility>

#include <cerrno>
#include <cstddef>

namespace {

// The chunk offset embedded in one URI's own trailing path segments, if
// any -- see Target::Path's own doc comment in target.hpp. Deliberately
// calling Target's own parse_path() (a static method, not tied to an
// instance) rather than duplicating the parsing logic here a third time:
// Chunk::create() takes `offset` as a plain scalar, so
// Object::_chunk() below (like Target::open()) extracts it from its own
// already-validated URI group once here, rather than Chunk::create()
// re-parsing it out of every URI itself.
uint64_t extract_offset(const rawstd::URI& uri) {
    return rawstor::Target::parse_path(uri).offset;
}

// The bound URI with its own identity path segments stripped back off --
// the bare location Chunk::create() itself expects, now that it no
// longer takes `id`/`offset` embedded in its own URI list (both are
// already separate parameters there). Calls URI::parent() once per
// identity segment, not just once, since the identity doesn't always
// fit in a single trailing one.
rawstd::URI strip_path(const rawstd::URI& uri) {
    rawstor::Target::Path path = rawstor::Target::parse_path(uri);
    rawstd::URI ret = uri;
    for (unsigned int i = 0; i < path.segments; ++i) {
        ret = ret.parent();
    }
    return ret;
}

} // namespace

namespace rawstor {

std::vector<Object::VolumeSegment>
Object::SingleChunkMap::segments(off_t offset, size_t size) const {
    return {VolumeSegment{0, offset, size, 0}};
}

std::vector<Object::VolumeSegment>
Object::MultiChunkMap::segments(off_t offset, size_t size) const {
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

Object::Object(
    rawio::Queue& queue, uint64_t size, std::unique_ptr<ChunkMap> map,
    std::vector<std::vector<rawstd::URI>> chunk_targets
) :
    _queue(queue),
    _size(size),
    _map(std::move(map)) {
    _chunks.resize(chunk_targets.size());
    for (size_t i = 0; i < chunk_targets.size(); ++i) {
        _chunks[i].targets = std::move(chunk_targets[i]);
    }
}

Object::~Object() = default;

rawstd::Task<Chunk*> Object::_chunk(uint32_t index) {
    ChunkEntry& entry = _chunks.at(index);

    if (entry.chunk != nullptr) {
        co_return entry.chunk.get();
    }

    if (entry.gate.running()) {
        co_await entry.gate.settle();
        if (entry.chunk == nullptr) {
            RAWSTD_THROW_SYSTEM_ERROR(
                entry.open_errno != 0 ? entry.open_errno : EIO
            );
        }
        co_return entry.chunk.get();
    }

    entry.gate.begin();
    std::exception_ptr error;
    try {
        RawstdUUID id = Target::parse_path(entry.targets.front()).id;
        uint64_t offset = extract_offset(entry.targets.front());
        std::vector<rawstd::URI> locations;
        locations.reserve(entry.targets.size());
        for (const auto& target : entry.targets) {
            locations.push_back(strip_path(target));
        }
        entry.chunk = co_await Chunk::create(locations, _queue, id, offset);
    } catch (const std::system_error& e) {
        entry.open_errno = e.code().value();
        error = std::current_exception();
    } catch (...) {
        entry.open_errno = EIO;
        error = std::current_exception();
    }
    entry.gate.end();

    if (error) {
        std::rethrow_exception(error);
    }
    co_return entry.chunk.get();
}

rawstd::Task<size_t> Object::_rw_segments(
    const std::vector<VolumeSegment>& segments, bool write, bool sync, void* buf
) {
    auto rw_one = [this, write, sync,
                   buf](VolumeSegment segment) -> rawstd::Task<size_t> {
        Chunk* chunk = co_await _chunk(segment.index);
        char* at = static_cast<char*>(buf) + segment.buf_offset;
        if (write) {
            co_return co_await chunk->pwrite(
                at, segment.size, segment.chunk_offset, sync
            );
        }
        co_return co_await chunk->pread(at, segment.size, segment.chunk_offset);
    };

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(segments.size());
    for (const VolumeSegment& segment : segments) {
        tasks.push_back(rw_one(segment));
    }
    std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
    size_t total = 0;
    for (size_t r : results) {
        total += r;
    }
    co_return total;
}

rawstd::Task<size_t> Object::pread(void* buf, size_t size, off_t offset) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments = _map->segments(offset, size);
    co_return co_await _rw_segments(segments, false, /*sync=*/false, buf);
}

rawstd::Task<size_t>
Object::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments = _map->segments(offset, size);
    co_return co_await _rw_segments(
        segments, true, sync, const_cast<void*>(buf)
    );
}

rawstd::Task<size_t>
Object::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments = _map->segments(offset, size);

    if (segments.size() == 1) {
        const VolumeSegment& segment = segments.front();
        Chunk* chunk = co_await _chunk(segment.index);
        co_return co_await chunk->preadv(iov, niov, size, segment.chunk_offset);
    }

    /* Cross-chunk vectored I/O bounces through a flat buffer (rare). */
    std::vector<char> bounce(size);
    size_t result =
        co_await _rw_segments(segments, false, false, bounce.data());
    iovec src = {bounce.data(), size};
    rawstd_iovec_to_iovec(&src, 1, 0, iov, niov);
    co_return result;
}

rawstd::Task<size_t> Object::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments = _map->segments(offset, size);

    if (segments.size() == 1) {
        const VolumeSegment& segment = segments.front();
        Chunk* chunk = co_await _chunk(segment.index);
        co_return co_await chunk->pwritev(
            iov, niov, size, segment.chunk_offset, sync
        );
    }

    std::vector<char> bounce(size);
    rawstd_iovec_to_buf(iov, niov, 0, bounce.data(), size);
    co_return co_await _rw_segments(segments, true, sync, bounce.data());
}

rawstd::Task<size_t> Object::discard(size_t size, off_t offset) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments = _map->segments(offset, size);

    auto discard_one = [this](VolumeSegment s) -> rawstd::Task<size_t> {
        Chunk* chunk = co_await _chunk(s.index);
        co_return co_await chunk->discard(s.size, s.chunk_offset);
    };

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(segments.size());
    for (const VolumeSegment& segment : segments) {
        tasks.push_back(discard_one(segment));
    }
    std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
    size_t total = 0;
    for (size_t r : results) {
        total += r;
    }
    co_return total;
}

rawstd::Task<size_t>
Object::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    if (static_cast<uint64_t>(offset) + size > _size) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::vector<VolumeSegment> segments = _map->segments(offset, size);

    auto write_zeroes_one = [this, unmap,
                             sync](VolumeSegment s) -> rawstd::Task<size_t> {
        Chunk* chunk = co_await _chunk(s.index);
        co_return co_await chunk->write_zeroes(
            s.size, s.chunk_offset, unmap, sync
        );
    };

    std::vector<rawstd::Task<size_t>> tasks;
    tasks.reserve(segments.size());
    for (const VolumeSegment& segment : segments) {
        tasks.push_back(write_zeroes_one(segment));
    }
    std::vector<size_t> results = co_await rawstd::gather(std::move(tasks));
    size_t total = 0;
    for (size_t r : results) {
        total += r;
    }
    co_return total;
}

rawstd::Task<void> Object::flush() {
    std::vector<rawstd::Task<void>> tasks;
    for (ChunkEntry& entry : _chunks) {
        if (entry.chunk != nullptr) {
            tasks.push_back(entry.chunk->flush());
        }
    }
    co_await rawstd::gather(std::move(tasks));
}

rawstd::Task<void> Object::close() {
    std::vector<rawstd::Task<void>> tasks;
    for (ChunkEntry& entry : _chunks) {
        if (entry.chunk != nullptr) {
            tasks.push_back(entry.chunk->close());
        }
    }
    co_await rawstd::gather(std::move(tasks));
    for (ChunkEntry& entry : _chunks) {
        entry.chunk.reset();
    }
}

} // namespace rawstor

namespace {

// C ABI adapters for the I/O group (rawstor_object_pread/_preadv/_pwrite/
// _pwritev): launch a detached coroutine that co_await's the
// already-submitted rawstd::Task, catches std::system_error, and invokes
// the originally-passed completion callback with the translated result --
// the same one-layer-up shape as librawio/src/rawio.cpp's
// launch_size_op_coro(). A negative return from the C callback throws --
// see the non-coroutine launch_io_op() wrapper below (not this function)
// for how that's actually delivered back out; see rawstd::DetachedTask's
// own doc comment for why the indirection exists.
rawstd::DetachedTask launch_io_op_coro(
    rawstd::Task<size_t> t, int (*cb)(size_t result, int error, void* data),
    void* data
) {
    size_t result = 0;
    int error = 0;
    try {
        result = co_await t;
    } catch (const std::system_error& e) {
        error = e.code().value();
    }
    int res = cb(result, error, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_io_op(
    rawstd::Task<size_t> t, int (*cb)(size_t result, int error, void* data),
    void* data
) {
    launch_io_op_coro(std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_object_flush(): same launch pattern as
// launch_io_op_coro() above, but flush()'s own callback shape collapses
// onto a single ssize_t result (negative -> -errno, zero -> success --
// there's nothing else to report) rather than the I/O group's separate
// result/error pair.
rawstd::DetachedTask launch_flush_op_coro(
    rawstd::Task<void> t, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_flush_op(
    rawstd::Task<void> t, int (*cb)(ssize_t result, void* data), void* data
) {
    launch_flush_op_coro(std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

// C ABI adapter for rawstor_object_close(): same shape as
// launch_flush_op_coro(), but unlike every other adapter here, `object`
// is deleted once its close() Task completes (successfully or not),
// before `cb` is invoked. `object` is not passed to `cb` at all: by the
// time `cb` runs, it no longer identifies anything usable, and the caller
// already knows which close this is (it's the one they just called
// rawstor_object_close() for).
rawstd::DetachedTask launch_close_op_coro(
    RawstorObject* object, rawstd::Task<void> t,
    int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await t;
    } catch (const std::system_error& e) {
        result = -e.code().value();
    }
    delete static_cast<rawstor::Object*>(object);
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

void launch_close_op(
    RawstorObject* object, rawstd::Task<void> t,
    int (*cb)(ssize_t result, void* data), void* data
) {
    launch_close_op_coro(object, std::move(t), cb, data);
    rawstd::DetachedTask::rethrow_if_pending();
}

} // namespace

int rawstor_object_close(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_close_op(
            object, static_cast<rawstor::Object*>(object)->close(), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->pread(buf, size, offset), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->preadv(
                iov, niov, size, offset
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    bool sync, int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->pwrite(
                buf, size, offset, sync
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, const iovec* iov, unsigned int niov, size_t size,
    off_t offset, bool sync, int (*cb)(size_t result, int error, void* data),
    void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->pwritev(
                iov, niov, size, offset, sync
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_discard(
    RawstorObject* object, size_t size, off_t offset,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->discard(size, offset), cb,
            data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_write_zeroes(
    RawstorObject* object, size_t size, off_t offset, bool unmap, bool sync,
    int (*cb)(size_t result, int error, void* data), void* data
) noexcept {
    try {
        launch_io_op(
            static_cast<rawstor::Object*>(object)->write_zeroes(
                size, offset, unmap, sync
            ),
            cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_flush(
    RawstorObject* object, int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    try {
        launch_flush_op(
            static_cast<rawstor::Object*>(object)->flush(), cb, data
        );
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc& e) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}
