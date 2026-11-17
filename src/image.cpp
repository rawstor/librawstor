#include "object.hpp"
#include "target.hpp"

#include <rawstor/target.h>

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <exception>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>
#include <cstdint>
#include <cstring>

#include <fcntl.h>

// Images: a whole object -- or one of its versions -- as a plain file, and
// a new object filled from a file or from another object (version). Data
// moves in sequential blocks through the ordinary Object read/write path,
// so every backend, mirrored or not, works the same way.
//
// Nothing here coordinates with other users of the objects involved: an
// object that is open elsewhere and has unflushed writes is read as the
// storage currently holds it, and the caller is responsible for quiescing
// it first (or exporting a version, which is a consistent point).

namespace {

// The unit data moves in, both directions.
const size_t block_size = 1024 * 1024;

bool is_zero(const char* buf, size_t size) {
    return size == 0 || (buf[0] == 0 && memcmp(buf, buf + 1, size - 1) == 0);
}

size_t block_at(uint64_t offset, uint64_t size) {
    return static_cast<size_t>(std::min<uint64_t>(block_size, size - offset));
}

// Reads exactly `size` bytes at `offset`; a read that makes no progress is
// EIO, so a short object cannot spin this forever.
rawstd::Task<void>
read_object(rawstor::Object& object, char* buf, size_t size, uint64_t offset) {
    size_t done = 0;
    while (done < size) {
        size_t n =
            co_await object.pread(buf + done, size - done, offset + done);
        if (n == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        done += n;
    }
}

rawstd::Task<void> write_object(
    rawstor::Object& object, const char* buf, size_t size, uint64_t offset
) {
    size_t done = 0;
    while (done < size) {
        size_t n = co_await object.pwrite(
            buf + done, size - done, offset + done, false
        );
        if (n == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        done += n;
    }
}

rawstd::Task<void> write_file(
    rawio::Queue& queue, int fd, const char* buf, size_t size, uint64_t offset
) {
    size_t done = 0;
    while (done < size) {
        size_t n = co_await queue.pwrite(
            fd, buf + done, size - done, static_cast<off_t>(offset + done),
            false
        );
        if (n == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        done += n;
    }
}

rawstd::Task<void> read_file(
    rawio::Queue& queue, int fd, char* buf, size_t size, uint64_t offset
) {
    size_t done = 0;
    while (done < size) {
        size_t n = co_await queue.pread(
            fd, buf + done, size - done, static_cast<off_t>(offset + done)
        );
        if (n == 0) {
            // The file shrank after its size was taken.
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
        done += n;
    }
}

// Copies `size` bytes of `source` into the file `fd`. With `sparse` (a
// regular file, already sized) an all-zero block is left as a hole instead
// of being written.
rawstd::Task<void> copy_object_to_file(
    rawio::Queue& queue, rawstor::Object& source, int fd, uint64_t size,
    bool sparse
) {
    std::vector<char> buf(block_size);
    for (uint64_t offset = 0; offset < size; offset += block_size) {
        size_t n = block_at(offset, size);
        co_await read_object(source, buf.data(), n, offset);
        if (sparse && is_zero(buf.data(), n)) {
            continue;
        }
        co_await write_file(queue, fd, buf.data(), n, offset);
    }
}

rawstd::Task<void> copy_file_to_object(
    rawio::Queue& queue, int fd, rawstor::Object& destination, uint64_t size
) {
    std::vector<char> buf(block_size);
    for (uint64_t offset = 0; offset < size; offset += block_size) {
        size_t n = block_at(offset, size);
        co_await read_file(queue, fd, buf.data(), n, offset);
        co_await write_object(destination, buf.data(), n, offset);
    }
}

rawstd::Task<void> copy_object_to_object(
    rawstor::Object& source, rawstor::Object& destination, uint64_t size
) {
    std::vector<char> buf(block_size);
    for (uint64_t offset = 0; offset < size; offset += block_size) {
        size_t n = block_at(offset, size);
        co_await read_object(source, buf.data(), n, offset);
        co_await write_object(destination, buf.data(), n, offset);
    }
}

// Size of a file as a reader sees it: st_size for a regular file, the
// device size for a block device.
uint64_t file_size(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    if (S_ISREG(st.st_mode)) {
        return static_cast<uint64_t>(st.st_size);
    }
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) {
        RAWSTD_THROW_ERRNO();
    }
    return static_cast<uint64_t>(end);
}

// The size of the new object: the source's own unless the caller asks for
// a larger one (the tail then reads back as zero).
uint64_t image_size(const RawstorObjectSpec& sp, uint64_t source_size) {
    if (sp.size == 0) {
        return source_size;
    }
    if (sp.size < source_size) {
        rawstd_error(
            "Spec size (%llu) is smaller than the source (%llu)\n",
            static_cast<unsigned long long>(sp.size),
            static_cast<unsigned long long>(source_size)
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return sp.size;
}

// Every parameter is taken by value: the task outlives the caller's frame.
rawstd::Task<void>
export_image(rawio::Queue* queue, rawstor::Target source, std::string path) {
    RawstorObjectSpec sp = co_await source.spec(*queue);
    std::unique_ptr<rawstor::Object> object =
        co_await source.open(*queue, RAWSTOR_READONLY);

    std::exception_ptr error;
    int fd = -1;
    try {
        fd = co_await queue->open(
            path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644
        );
        struct stat st;
        if (fstat(fd, &st) < 0) {
            RAWSTD_THROW_ERRNO();
        }
        bool sparse = S_ISREG(st.st_mode);
        if (sparse && ftruncate(fd, static_cast<off_t>(sp.size)) < 0) {
            RAWSTD_THROW_ERRNO();
        }
        co_await copy_object_to_file(*queue, *object, fd, sp.size, sparse);
        co_await queue->fsync(fd, false);
    } catch (...) {
        error = std::current_exception();
    }
    if (fd >= 0) {
        try {
            co_await queue->close(fd);
        } catch (...) {
            if (!error) {
                error = std::current_exception();
            }
        }
    }
    try {
        co_await object->close();
    } catch (...) {
        if (!error) {
            error = std::current_exception();
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
}

// What a new object is filled from: a file, or another object (version).
struct ImageSource {
    std::string path;
    std::optional<rawstor::Target> target;
};

// Creates `destination` and fills it from `from`. A failure once the object
// exists removes it again, so a failed import leaves nothing behind.
rawstd::Task<void> create_from(
    rawio::Queue* queue, rawstor::Target destination, RawstorObjectSpec sp,
    ImageSource from
) {
    int fd = -1;
    std::unique_ptr<rawstor::Object> source;
    uint64_t source_size = 0;

    std::exception_ptr error;
    try {
        if (!from.target) {
            fd = co_await queue->open(
                from.path.c_str(), O_RDONLY | O_CLOEXEC, 0
            );
            source_size = file_size(fd);
        } else {
            RawstorObjectSpec source_spec = co_await from.target->spec(*queue);
            source_size = source_spec.size;
            source = co_await from.target->open(*queue, RAWSTOR_READONLY);
        }
        sp.size = image_size(sp, source_size);
    } catch (...) {
        error = std::current_exception();
    }

    bool created = false;
    std::unique_ptr<rawstor::Object> object;
    if (!error) {
        try {
            co_await destination.create(*queue, sp);
            created = true;
            object = co_await destination.open(*queue, 0);
            if (!from.target) {
                co_await copy_file_to_object(*queue, fd, *object, source_size);
            } else {
                co_await copy_object_to_object(*source, *object, source_size);
            }
            co_await object->flush();
        } catch (...) {
            error = std::current_exception();
        }
    }

    if (object) {
        try {
            co_await object->close(!error);
        } catch (...) {
            if (!error) {
                error = std::current_exception();
            }
        }
    }
    if (fd >= 0) {
        try {
            co_await queue->close(fd);
        } catch (...) {
        }
    }
    if (source) {
        try {
            co_await source->close();
        } catch (...) {
        }
    }
    if (error && created) {
        try {
            co_await destination.remove(*queue);
        } catch (...) {
            rawstd_error("Failed to remove the partially created object\n");
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
}

// Same shape as launch_create_op_coro() in target.cpp: the result goes to
// `cb`, every exception becomes an errno.
rawstd::DetachedTask launch_image_op_coro(
    rawstd::Task<void> task, int (*cb)(ssize_t result, void* data), void* data
) {
    ssize_t result = 0;
    try {
        co_await std::move(task);
    } catch (const std::system_error& e) {
        result = -e.code().value();
    } catch (const std::bad_alloc&) {
        result = -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        result = -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        result = -EINVAL;
    }
    int res = cb(result, data);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

// Common tail of the three entry points: validates and parses what can fail
// synchronously, launches, and maps a synchronous failure to an errno.
template <typename F>
int submit(F&& make_task, int (*cb)(ssize_t, void*), void* data) {
    try {
        launch_image_op_coro(make_task(), cb, data);
        rawstd::DetachedTask::rethrow_if_pending();
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

} // namespace

int rawstor_target_export(
    RawIOQueue* queue, const char* target, const char* path,
    int (*cb)(ssize_t result, void* data), void* data
) noexcept {
    return submit(
        [&] {
            if (path == nullptr) {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
            return export_image(
                static_cast<rawio::Queue*>(queue),
                rawstor::Target(rawstd::URI::uriv(target)), path
            );
        },
        cb, data
    );
}

int rawstor_target_create_from_file(
    RawIOQueue* queue, const char* target, const char* path,
    const struct RawstorObjectSpec* spec, int (*cb)(ssize_t result, void* data),
    void* data
) noexcept {
    return submit(
        [&] {
            if (path == nullptr) {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
            return create_from(
                static_cast<rawio::Queue*>(queue),
                rawstor::Target(rawstd::URI::uriv(target)),
                spec != nullptr ? *spec : RawstorObjectSpec{},
                ImageSource{path, std::nullopt}
            );
        },
        cb, data
    );
}

int rawstor_target_create_from_target(
    RawIOQueue* queue, const char* target, const char* source,
    const struct RawstorObjectSpec* spec, int (*cb)(ssize_t result, void* data),
    void* data
) noexcept {
    return submit(
        [&] {
            if (source == nullptr) {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
            return create_from(
                static_cast<rawio::Queue*>(queue),
                rawstor::Target(rawstd::URI::uriv(target)),
                spec != nullptr ? *spec : RawstorObjectSpec{},
                ImageSource{
                    std::string(), rawstor::Target(rawstd::URI::uriv(source))
                }
            );
        },
        cb, data
    );
}
