#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>

#include <functional>
#include <memory>
#include <vector>

namespace rawstor {

class Connection;

} // namespace rawstor

struct RawstorObject final {
private:
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

    explicit RawstorObject(const std::vector<rawstd::URI>& targets);
    RawstorObject(const RawstorObject&) = delete;
    RawstorObject(RawstorObject&&) = delete;
    RawstorObject& operator=(const RawstorObject&) = delete;
    RawstorObject& operator=(RawstorObject&&) = delete;

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

#endif // RAWSTOR_OBJECT_HPP
