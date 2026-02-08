#ifndef RAWSTOR_OST_SESSION_HPP
#define RAWSTOR_OST_SESSION_HPP

#include "ost_protocol.h"
#include "session.hpp"

#include <rawstorstd/ringbuf.hpp>
#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <string>
#include <unordered_map>

#include <cstddef>

namespace rawstor {
namespace ost {

class Context;

class Session final : public rawstor::Session {
private:
    RawstorObject* _o;
    uint16_t _cid_counter;

    std::shared_ptr<Context> _context;

    int _connect();

public:
    Session(const URI& uri, unsigned int depth);
    ~Session();

    void read_response_head(rawstor::io::Queue& queue);
    void read_response_body(
        rawstor::io::Queue& queue, void* buf, size_t size
    );
    void read_response_body(
        rawstor::io::Queue& queue, iovec* iov, unsigned int niov,
        size_t size
    );

    void create(
        rawstor::io::Queue& queue, const RawstorUUID& id,
        const RawstorObjectSpec& sp, std::unique_ptr<rawstor::Task> t
    ) override;

    void remove(
        rawstor::io::Queue& queue, const RawstorUUID& id,
        std::unique_ptr<rawstor::Task> t
    ) override;

    void spec(
        rawstor::io::Queue& queue, const RawstorUUID& id, RawstorObjectSpec* sp,
        std::unique_ptr<rawstor::Task> t
    ) override;

    void set_object(
        rawstor::io::Queue& queue, RawstorObject* object,
        std::unique_ptr<rawstor::Task> t
    ) override;

    void pread(std::unique_ptr<rawstor::TaskScalar> t) override;

    void preadv(std::unique_ptr<rawstor::TaskVector> t) override;

    void pwrite(std::unique_ptr<rawstor::TaskScalar> t) override;

    void pwritev(std::unique_ptr<rawstor::TaskVector> t) override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_SESSION_HPP
