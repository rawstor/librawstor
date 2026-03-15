#ifndef RAWSTOR_FILE_SESSION_HPP
#define RAWSTOR_FILE_SESSION_HPP

#include "session.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/uri.hpp>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

namespace rawstor {
namespace file {

class Session final : public rawstor::Session {
private:
    int _connect(const RawstorUUID& id);

public:
    Session(rawstor::io::Queue& queue, const URI& uri, unsigned int depth);

    void create(
        const RawstorUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstorUUID& id, std::function<void(int)>&& cb) override;

    void spec(
        const RawstorUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) override;

    void set_object(RawstorObject* object) override;

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;
};

} // namespace file
} // namespace rawstor

#endif // RAWSTOR_FILE_SESSION_HPP
