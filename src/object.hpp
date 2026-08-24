#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

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

    // Object is final -- unlike Session::Private (which every backend
    // subclass's own constructor also needs to name), nothing but
    // create() itself ever needs this, so it stays private rather than
    // protected.
    struct Private {
        explicit Private() = default;
    };

public:
    // Creates a Connection (with its own session pool) against every
    // target and open()s each -- the returned Object's data-path methods
    // are ready for use. By analogy with Connection::create(): the heavy
    // async work lives here, not in the constructor.
    static rawstd::Task<std::unique_ptr<Object>>
    create(rawio::Queue& queue, const std::vector<rawstd::URI>& targets);

    Object(
        Private, rawio::Queue& queue, const std::vector<rawstd::URI>& targets
    );
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
