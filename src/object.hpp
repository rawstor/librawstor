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
    rawio::Queue& _queue;
    RawstdUUID _id;
    std::vector<std::unique_ptr<rawstor::Connection>> _cns;

public:
    static void create(
        const std::vector<rawstd::URI>& locations, const RawstorObjectSpec& sp,
        std::vector<rawstd::URI>* targets
    );
    static void remove(const std::vector<rawstd::URI>& targets);
    static void
    spec(const std::vector<rawstd::URI>& targets, RawstorObjectSpec* sp);

    Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);
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
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
