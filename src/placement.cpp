#include "placement.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include <cerrno>
#include <cmath>
#include <cstring>

namespace {

using rawstor::mds::TopologyOST;

/* Domain-vs-leaf inputs must never collide on equal names. */
constexpr uint8_t TAG_DOMAIN = 0xd0;
constexpr uint8_t TAG_LEAF = 0x1f;

struct Domain {
    std::string key;
    uint64_t weight = 0; /* aggregated over the leaves */
    std::vector<const TopologyOST*> leaves;
};

uint64_t hrw_hash(
    uint8_t tag, uint64_t seed, const RawstdUUID& volume_id,
    const uint64_t* index, const std::string& name
) {
    std::vector<unsigned char> buf;
    buf.reserve(1 + sizeof(seed) + sizeof(volume_id.bytes) + 8 + name.size());

    buf.push_back(tag);
    for (unsigned i = 0; i < 8; ++i) {
        buf.push_back(static_cast<unsigned char>(seed >> (8 * i)));
    }
    buf.insert(
        buf.end(), volume_id.bytes, volume_id.bytes + sizeof(volume_id.bytes)
    );
    if (index != nullptr) {
        for (unsigned i = 0; i < 8; ++i) {
            buf.push_back(static_cast<unsigned char>(*index >> (8 * i)));
        }
    }
    buf.insert(buf.end(), name.begin(), name.end());

    return rawstd_hash_scalar(buf.data(), buf.size());
}

/*
 * Weighted rendezvous score: u uniform in (0,1) from the hash, the winner
 * is the largest -w/ln(u). Zero weights are filtered out before scoring.
 */
double hrw_score(uint64_t hash, uint64_t weight) {
    double u = (static_cast<double>(hash) + 0.5) / 18446744073709551616.0;
    return -static_cast<double>(weight) / std::log(u);
}

} // namespace

namespace rawstor {
namespace mds {

std::vector<PlacementSlot> place(
    const Topology& topology, const RawstdUUID& volume_id, uint64_t index,
    const PlacementPolicy& policy
) {
    if (policy.width == 0) {
        rawstd_error("Placement width 0\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    /* std::map: deterministic iteration for equal inputs. */
    std::map<std::string, Domain> domains;
    for (const TopologyOST& ost : topology.osts()) {
        if (ost.weight == 0) {
            continue;
        }
        std::string key = ost.domain(policy.failure_domain);
        Domain& d = domains[key];
        d.key = key;
        d.weight += ost.weight;
        d.leaves.push_back(&ost);
    }

    /* Unsatisfiable topology hard-fails: never under-protect silently. */
    if (domains.size() < policy.width) {
        rawstd_error(
            "Unsatisfiable placement: %zu populated failure domains, "
            "width %u\n",
            domains.size(), policy.width
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    const bool index_in_key = policy.stripe_width != 1;
    const uint64_t* chunk_index = index_in_key ? &index : nullptr;

    std::vector<const Domain*> pool;
    pool.reserve(domains.size());
    for (const auto& i : domains) {
        pool.push_back(&i.second);
    }

    /*
     * A partial stripe pins a pool of max(K, width) domains per volume;
     * chunks then spread within it. K=1 degenerates to a pool of exactly
     * width domains — every chunk on the same OSTs. K=all keeps every
     * domain in play.
     */
    auto rank = [&](uint8_t tag, const uint64_t* idx) {
        return [&, tag, idx](const Domain* a, const Domain* b) {
            double sa = hrw_score(
                hrw_hash(tag, policy.seed, volume_id, idx, a->key), a->weight
            );
            double sb = hrw_score(
                hrw_hash(tag, policy.seed, volume_id, idx, b->key), b->weight
            );
            if (sa != sb) {
                return sa > sb;
            }
            return a->key < b->key;
        };
    };

    if (policy.stripe_width != STRIPE_ALL) {
        size_t pool_size = static_cast<size_t>(
            std::max<uint64_t>(policy.stripe_width, policy.width)
        );
        if (pool_size < pool.size()) {
            std::partial_sort(
                pool.begin(), pool.begin() + pool_size, pool.end(),
                rank(TAG_DOMAIN, nullptr)
            );
            pool.resize(pool_size);
        }
    }

    std::partial_sort(
        pool.begin(), pool.begin() + policy.width, pool.end(),
        rank(TAG_DOMAIN, chunk_index)
    );

    std::vector<PlacementSlot> ret;
    ret.reserve(policy.width);

    for (unsigned slot = 0; slot < policy.width; ++slot) {
        const Domain& domain = *pool[slot];

        const TopologyOST* best = nullptr;
        double best_score = 0;
        for (const TopologyOST* leaf : domain.leaves) {
            RawstdUUIDString s;
            rawstd_uuid_to_string(&leaf->id, &s);
            double leaf_score = hrw_score(
                hrw_hash(TAG_LEAF, policy.seed, volume_id, chunk_index, s),
                leaf->weight
            );
            if (best == nullptr || leaf_score > best_score) {
                best = leaf;
                best_score = leaf_score;
            }
        }

        ret.push_back(
            PlacementSlot{
                static_cast<uint8_t>(slot),
                best->id,
            }
        );
    }

    return ret;
}

} // namespace mds
} // namespace rawstor
