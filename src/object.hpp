#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <functional>
#include <memory>
#include <vector>

struct RawstorObject {};

namespace rawstor {

class Connection;

class Object final : public RawstorObject {
private:
    struct OpenState;

    rawio::Queue& _queue;
    RawstdUUID _id;
    std::vector<std::unique_ptr<rawstor::Connection>> _cns;

    Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);

    void _open_next(const std::shared_ptr<OpenState>& st);

public:
    static void open(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        std::function<void(Object*, int)>&& cb
    );

    static void create(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        const RawstorObjectSpec& sp, std::function<void(int)>&& cb
    );
    static void remove(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        std::function<void(int)>&& cb
    );
    static void spec(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        RawstorObjectSpec* sp, std::function<void(int)>&& cb
    );
    static void meta(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        RawstorObjectMeta* meta, std::function<void(int)>&& cb
    );
    static void set_state(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        const RawstorObjectMeta& meta, std::function<void(int)>&& cb
    );

    static void create(
        const std::vector<rawstd::URI>& targets, const RawstorObjectSpec& sp
    );
    static void remove(const std::vector<rawstd::URI>& targets);
    static void
    spec(const std::vector<rawstd::URI>& targets, RawstorObjectSpec* sp);
    static void
    meta(const std::vector<rawstd::URI>& targets, RawstorObjectMeta* meta);
    static void set_state(
        const std::vector<rawstd::URI>& targets, const RawstorObjectMeta& meta
    );

    Object(const Object&) = delete;
    Object(Object&&) = delete;
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    std::vector<rawstd::URI> locations() const;

    inline const RawstdUUID& id() const noexcept { return _id; }

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void flush(std::function<void(size_t, int)>&& cb);
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
