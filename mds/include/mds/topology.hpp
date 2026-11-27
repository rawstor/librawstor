#ifndef RAWSTOR_MDS_TOPOLOGY_HPP
#define RAWSTOR_MDS_TOPOLOGY_HPP

#include <rawstd/uuid.h>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace rawstor {
namespace mdsserver {

/*
 * Topology tree levels (docs/mds.md, "Placement function"):
 * root -> dc -> row -> rack -> server -> ost(leaf). A failure domain is a
 * subtree at one of these levels; OST is the degenerate per-leaf domain
 * (useful for single-host and test setups). Same values as
 * RAWSTOR_OBJ_DOMAIN_* (<rawstor/protocol.h>), numbered from the leaf up.
 */
enum class Level : unsigned {
    OST = 1,
    Server = 2,
    Rack = 3,
    Row = 4,
    DC = 5,
};

/* Throws EINVAL unless `value` is one of Level's values. */
Level level_of(unsigned value);

enum class Role { Data, Witness };

struct TopologyOST {
    RawstdUUID id;
    /* A rawstor location URI (ost://host:port, ...); the client opens
     * the chunks this OST holds through it. */
    std::string location;
    uint64_t weight;
    std::set<Role> roles{Role::Data, Role::Witness};
    std::string path[4]; /* dc, row, rack, server; "" = not given */

    /* Domain identity at a level: the full path prefix (not the last
     * component alone: two "host1" in different racks are different
     * domains). */
    std::string domain(Level level) const;
    bool supports(Role role) const { return roles.contains(role); }
    bool witness_only() const { return !supports(Role::Data); }
};

/*
 * The OSTs mds:// objects are placed on (docs/mds.md, "OST registration"):
 * every OST that has registered with the MDS, a DATA and witness candidate
 * each, and the witness the MDS hosts itself. An entry's path goes from the
 * root down to the server it runs on; a level it leaves out is one implicit
 * domain shared by every entry that leaves it out too.
 */
class Topology final {
private:
    std::vector<TopologyOST> _osts;

public:
    /* Throws EEXIST on a duplicate ost id, EINVAL for an entry without a
     * role. */
    void add(const TopologyOST& ost);

    /* Retains only the given OST ids, preserving topology order. */
    Topology select(const std::vector<RawstdUUID>& ids) const;

    const std::vector<TopologyOST>& osts() const noexcept { return _osts; }
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_TOPOLOGY_HPP
