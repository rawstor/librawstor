#ifndef RAWSTOR_PLACEMENT_HPP
#define RAWSTOR_PLACEMENT_HPP

#include "topology.hpp"

#include <rawstd/uuid.h>

#include <cstdint>
#include <vector>

namespace rawstor {
namespace mds {

/* K = STRIPE_ALL spreads every chunk independently (Ceph-like). */
constexpr uint64_t STRIPE_ALL = 0;

struct PlacementPolicy {
    unsigned width;        /* slots per chunk: mirror R | ec k+m */
    Level failure_domain;  /* level at which slots must differ */
    uint64_t stripe_width; /* K; 1 = object-local, STRIPE_ALL = spread */
    uint64_t seed;
};

struct PlacementSlot {
    uint8_t slot_index;
    RawstdUUID ost_id;
};

/*
 * Deterministic placement generator (docs/mds.md, "Placement
 * function"): weighted rendezvous (HRW) over the topology tree. Used only
 * at create/grow and rebalance/recovery; the MDS map stays authoritative.
 *
 * The stripe_width knob is the HRW key shape:
 *   K=1    keys carry the object only: every chunk lands on the same OSTs
 *   K=all  keys carry (id, index): every chunk is independent
 *   K      an object-pinned pool of max(K, width) domains, chunks spread
 *          by (id, index) within it
 *
 * Slots are placed in width distinct failure domains; an unsatisfiable
 * policy (fewer populated domains than width) hard-fails with EINVAL —
 * never a silently under-protected placement.
 */
std::vector<PlacementSlot> place(
    const Topology& topology, const RawstdUUID& id, uint64_t index,
    const PlacementPolicy& policy
);

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_PLACEMENT_HPP
