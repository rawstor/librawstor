#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <list>
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
    static rawstd::Task<void> list(
        rawio::Queue& queue, const std::vector<rawstd::URI>& locations,
        unsigned int limit, std::list<std::vector<rawstd::URI>>& targets,
        RawstorPaginationToken& token
    );
    static rawstd::Task<RawstorLocationInfo>
    info(rawio::Queue& queue, const std::vector<rawstd::URI>& locations);
    static rawstd::Task<void> create(
        rawio::Queue& queue, const std::vector<rawstd::URI>& targets,
        const RawstorObjectSpec& sp
    );
    static rawstd::Task<void>
    remove(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);
    static rawstd::Task<RawstorObjectSpec>
    spec(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);

    Object(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);
    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object();
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    std::vector<rawstd::URI> locations() const;

    inline const RawstdUUID& id() const noexcept { return _id; }

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset);

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset);

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync);

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    );

    rawstd::Task<void> flush();
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
