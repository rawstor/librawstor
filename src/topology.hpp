#ifndef RAWSTOR_TOPOLOGY_HPP
#define RAWSTOR_TOPOLOGY_HPP

#include <rawstd/uuid.h>

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace rawstor {
namespace mds {

/*
 * Topology tree levels (rawstor_docs/Mds.md, "Placement function"):
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
    std::string address; /* host:port; the client resolves it at open */
    uint64_t weight;
    std::string path[3]; /* dc, rack, server */

    /* Domain identity at a level: the full path prefix (not the last
     * component alone: two "host1" in different racks are different
     * domains). */
    std::string domain(Level level) const;
};

/*
 * The static topology config, v1 of the MGS role of rawstor_docs/Mds.md.
 * Line-based:
 *
 *   # ost <uuid> <host:port> <weight> <dc>/<rack>/<server>
 *   ost 00000000-0000-7000-8000-000000000001 127.0.0.1:8753 100 dc1/rack1/host1
 *
 * '#' comments and blank lines are skipped.
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

#endif // RAWSTOR_TOPOLOGY_HPP
