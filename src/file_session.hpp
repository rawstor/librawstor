#ifndef RAWSTOR_FILE_SESSION_HPP
#define RAWSTOR_FILE_SESSION_HPP

#include "session.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/uri.hpp>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

#include <string>

namespace rawstor {
namespace file {

class SessionOp;

class Session final : public rawstor::Session {
private:
    RawstorObject* _o;

    int _connect(const RawstorUUID& id);

public:
    Session(const URI& uri, unsigned int depth);

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

    void read(std::unique_ptr<rawstor::TaskScalar> t) override;

    void read(std::unique_ptr<rawstor::TaskVector> t) override;

    void write(std::unique_ptr<rawstor::TaskScalar> t) override;

    void write(std::unique_ptr<rawstor::TaskVector> t) override;
};

} // namespace file
} // namespace rawstor

#endif // RAWSTOR_FILE_SESSION_HPP
