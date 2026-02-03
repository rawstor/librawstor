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
    RawstorIOEvent* _read_event;
    uint16_t _cid_counter;

    std::shared_ptr<Context> _context;

    int _connect();

public:
    Session(rawstor::io::Queue& queue, const URI& uri, unsigned int depth);
    ~Session();

    void create(
        const RawstorUUID& id, const RawstorObjectSpec& sp,
        std::unique_ptr<rawstor::Task> t
    ) override;

    void
    remove(const RawstorUUID& id, std::unique_ptr<rawstor::Task> t) override;

    void spec(
        const RawstorUUID& id, RawstorObjectSpec* sp,
        std::unique_ptr<rawstor::Task> t
    ) override;

    void set_object(
        RawstorObject* object, std::unique_ptr<rawstor::Task> t
    ) override;

    void pread(std::unique_ptr<rawstor::TaskScalar> t) override;

    void preadv(std::unique_ptr<rawstor::TaskVector> t) override;

    void pwrite(std::unique_ptr<rawstor::TaskScalar> t) override;

    void pwritev(std::unique_ptr<rawstor::TaskVector> t) override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_SESSION_HPP
