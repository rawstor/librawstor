#ifndef RAWSTOR_FILE_SESSION_HPP
#define RAWSTOR_FILE_SESSION_HPP

#include "blk_session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <functional>
#include <list>

namespace rawstor {
namespace file {

class Session final : public rawstor::blk::Session {
private:
    void _connect(
        const RawstdUUID& id, uint64_t snap, std::function<void(int)>&& cb
    ) override;

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);

    void list(
        unsigned int limit, const RawstdUUID& token,
        std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&&
            cb
    ) override;

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;

    void spec(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) override;

    void meta(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;

    void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    ) override;

    void
    info(std::function<void(const RawstorLocationInfo&, int)>&& cb) override;

    void list_chunks(
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    ) override;

    /* No CoW on plain files: ENOTSUP (rawstor_docs/Mds.md, "Snapshots"). */
    void snapshot(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;

    void snap_remove(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;
};

} // namespace file
} // namespace rawstor

#endif // RAWSTOR_FILE_SESSION_HPP
