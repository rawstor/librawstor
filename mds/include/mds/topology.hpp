#ifndef RAWSTOR_MDS_TOPOLOGY_HPP
#define RAWSTOR_MDS_TOPOLOGY_HPP

#include <rawstd/uuid.h>

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace rawstor {
namespace mds {

/*
 * Topology tree levels (docs/mds.md, "Placement function"):
 * root -> dc -> rack -> server -> ost(leaf). A failure domain is a subtree
 * at one of these levels; OST is the degenerate per-leaf domain (useful for
 * single-host and test setups).
 */
enum class Level : unsigned {
    DC = 0,
    Rack = 1,
    Server = 2,
    OST = 3,
};

struct TopologyOST {
    RawstdUUID id;
    /* A rawstor location URI (ost://host:port, ...); the client opens
     * the chunks this OST holds through it. */
    std::string location;
    uint64_t weight;
    std::string path[3]; /* dc, rack, server */

    /* Domain identity at a level: the full path prefix (not the last
     * component alone: two "host1" in different racks are different
     * domains). */
    std::string domain(Level level) const;
};

/*
 * The static topology config, v1 of the MGS role of docs/mds.md.
 * Line-based:
 *
 *   # <ost-uuid> <location> <weight> <dc>/<rack>/<server>
 *   00000000-0000-7000-8000-000000000001 ost://host1:7777 100 dc1/r1/host1
 *
 * <location> is a single rawstor location URI of any scheme; it is
 * handed to clients as is, so a client-local one (file://, lvm://, zfs://)
 * only makes sense on a single host. '#' comments and blank lines are
 * skipped.
 */
class Topology final {
private:
    std::vector<TopologyOST> _osts;

public:
    static Topology parse(std::istream& in);
    static Topology parse_file(const std::string& path);

    /* Throws EEXIST on a duplicate ost id. */
    void add(const TopologyOST& ost);

    const std::vector<TopologyOST>& osts() const noexcept { return _osts; }
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_TOPOLOGY_HPP
