#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstorstd/uri.hpp>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

#include <memory>
#include <vector>

namespace rawstor {

class Connection;

} // namespace rawstor

struct RawstorObject final {
private:
    RawstorUUID _id;
    std::vector<std::unique_ptr<rawstor::Connection>> _cns;

public:
    static void create(
        const std::vector<rawstor::URI>& uris, const RawstorObjectSpec& sp,
        std::vector<rawstor::URI>* object_uris
    );
    static void remove(const std::vector<rawstor::URI>& uris);
    static void
    spec(const std::vector<rawstor::URI>& uris, RawstorObjectSpec* sp);

    explicit RawstorObject(const std::vector<rawstor::URI>& uris);
    RawstorObject(const RawstorObject&) = delete;
    RawstorObject(RawstorObject&&) = delete;
    RawstorObject& operator=(const RawstorObject&) = delete;
    RawstorObject& operator=(RawstorObject&&) = delete;

    std::vector<rawstor::URI> uris() const;

    inline const RawstorUUID& id() const noexcept { return _id; }

    void pread(
        void* buf, size_t size, off_t offset, RawstorCallback* cb, void* data
    );

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        RawstorCallback* cb, void* data
    );

    void pwrite(
        const void* buf, size_t size, off_t offset, RawstorCallback* cb,
        void* data
    );

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        RawstorCallback* cb, void* data
    );
};

#endif // RAWSTOR_OBJECT_HPP
