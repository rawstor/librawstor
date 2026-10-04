#ifndef RAWSTOR_MDS_TOPOLOGY_HPP
#define RAWSTOR_MDS_TOPOLOGY_HPP

#include <rawstd/uuid.h>

#include <cstdint>
#include <iosfwd>
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

struct TopologyOST {
    RawstdUUID id;
    /* A rawstor location URI (ost://host:port, ...); the client opens
     * the chunks this OST holds through it. */
    std::string location;
    uint64_t weight;
    std::string path[4]; /* dc, row, rack, server; "" = not given */

    /* Domain identity at a level: the full path prefix (not the last
     * component alone: two "host1" in different racks are different
     * domains). */
    std::string domain(Level level) const;
};

/*
 * The static topology config, v1 of the MGS role of docs/mds.md.
 * Line-based:
 *
 *   # <ost-uuid> <location> <weight> [[[<dc>/]<row>/]<rack>/]<server>
 *   00000000-0000-7000-8000-000000000001 ost://host1:7777 100 dc1/w1/r1/host1
 *
 * The path goes from the root down to the server the OST runs on; only
 * the server is required and the leading levels may be left out: a level
 * an entry leaves out is one implicit domain shared by every entry that
 * leaves it out too.
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

    /* Retains only the given OST ids, preserving topology order. */
    Topology select(const std::vector<RawstdUUID>& ids) const;

    const std::vector<TopologyOST>& osts() const noexcept { return _osts; }
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_TOPOLOGY_HPP
