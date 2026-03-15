#ifndef RAWSTOR_OST_SESSION_HPP
#define RAWSTOR_OST_SESSION_HPP

#include "ost_protocol.h"
#include "session.hpp"

#include <rawstorstd/ringbuf.hpp>
#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <cstddef>

namespace rawstor {
namespace ost {

class Context;

class Session final : public rawstor::Session {
private:
    uint16_t _cid_counter;

    std::shared_ptr<Context> _context;

    int _connect();

public:
    Session(rawstor::io::Queue& queue, const URI& uri, unsigned int depth);
    ~Session();

    void read_response_head();
    void read_response_body(void* buf, size_t size);
    void read_response_body(
        iovec* iov, unsigned int niov, size_t size
    );

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

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_SESSION_HPP
