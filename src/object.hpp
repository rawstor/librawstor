#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>

#include <memory>
#include <vector>

struct RawstorObject {};

namespace rawstor {

class Connection;
class Target;

class Object final : public RawstorObject {
private:
    rawio::Queue& _queue;
    std::vector<rawstd::URI> _uris;
    std::vector<std::unique_ptr<rawstor::Connection>> _cns;

    // Object is final -- unlike Session::Private (which every backend
    // subclass's own constructor also needs to name), only Target::open()
    // (a friend, since it's the one place that actually builds an Object)
    // ever needs this, so it stays private rather than protected.
    struct Private {
        explicit Private() = default;
    };

    friend class Target;

public:
    Object(
        Private, rawio::Queue& queue, const std::vector<rawstd::URI>& targets
    );
    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object();
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    // This Object's own target -- the same URIs (each already carrying
    // this Object's UUID) it was built from.
    Target target() const;

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
