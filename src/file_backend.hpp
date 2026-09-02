#ifndef RAWSTOR_FILE_BACKEND_HPP
#define RAWSTOR_FILE_BACKEND_HPP

#include "blk_backend.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/target.h>

#include <vector>

namespace rawstor {
namespace file {

class Backend final : public rawstor::blk::Backend {
private:
    rawstd::Task<int> _open(const RawstdUUID& id) override;

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) override;

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) override;

    rawstd::Task<void> remove(const RawstdUUID& id) override;

    rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) override;

    // Mirror consistency metadata lives in a companion "<uuid>.meta" file
    // next to the object's data file (see docs/mirroring.md) -- unlike
    // spec(), which is always derived straight from the data file's own
    // size, there is nowhere on a plain regular file to carve out space
    // for this without touching object data. A copy with no ".meta" file
    // (created before this existed) is not trusted as legacy-CLEAN: meta()
    // fails ENOENT rather than fabricating a state.
    rawstd::Task<RawstorObjectMeta> meta(const RawstdUUID& id) override;

    rawstd::Task<void>
    set_state(const RawstdUUID& id, const RawstorObjectMeta& meta) override;

    rawstd::Task<RawstorLocationInfo> info() override;
};

} // namespace file
} // namespace rawstor

#endif // RAWSTOR_FILE_BACKEND_HPP
