#include <mds/placement.hpp>
#include <mds/topology.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uuid.h>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <cstdio>

#include <gtest/gtest.h>

namespace {

using rawstor::mdsserver::Level;
using rawstor::mdsserver::place;
using rawstor::mdsserver::PlacementPolicy;
using rawstor::mdsserver::PlacementSlot;
using rawstor::mdsserver::STRIPE_ALL;
using rawstor::mdsserver::Topology;
using rawstor::mdsserver::TopologyOST;

TopologyOST make_ost(const char* id, uint64_t weight, const char* host) {
    TopologyOST ost{};
    if (rawstd_uuid_from_string(&ost.id, id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    ost.location = "ost://127.0.0.1:0";
    ost.weight = weight;
    ost.path[0] = "dc1";
    ost.path[1] = "row1";
    ost.path[2] = "rack1";
    ost.path[3] = host;
    return ost;
}

RawstdUUID make_id() {
    RawstdUUID id{};
    if (rawstd_uuid7_init(&id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    return id;
}

TEST(PlacementTest, rejects_width_zero) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    PlacementPolicy policy{0, Level::OST, 1, 0};

    EXPECT_THROW(place(topology, make_id(), 0, policy), std::system_error);
}

TEST(PlacementTest, rejects_unsatisfiable_width) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    // Only one populated OST-level domain -- width 2 can never be
    // satisfied (own doc comment, placement.hpp: "never a silently
    // under-protected placement").
    PlacementPolicy policy{2, Level::OST, 1, 0};

    EXPECT_THROW(place(topology, make_id(), 0, policy), std::system_error);
}

TEST(PlacementTest, zero_weight_ost_never_populates_a_domain) {
    Topology topology;
    topology.add(make_ost("00000000-0000-7000-8000-000000000001", 0, "host1"));
    PlacementPolicy policy{1, Level::OST, 1, 0};

    // The only OST has weight 0, so no failure domain is actually
    // populated -- same as an empty topology for width 1.
    EXPECT_THROW(place(topology, make_id(), 0, policy), std::system_error);
}

TEST(PlacementTest, single_ost_width_one) {
    Topology topology;
    RawstdUUID ost_id;
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &ost_id, "00000000-0000-7000-8000-000000000001"
        ),
        0
    );
    TopologyOST ost =
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1");
    topology.add(ost);
    PlacementPolicy policy{1, Level::OST, 1, 0};

    std::vector<PlacementSlot> slots = place(topology, make_id(), 0, policy);

    ASSERT_EQ(slots.size(), 1u);
    EXPECT_EQ(slots[0].slot_index, 0);
    EXPECT_EQ(rawstd_uuid_cmp(&slots[0].ost_id, &ost_id), 0);
}

TEST(PlacementTest, is_deterministic_for_the_same_inputs) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000002", 100, "host2")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000003", 100, "host3")
    );
    RawstdUUID id = make_id();
    PlacementPolicy policy{2, Level::OST, 1, 42};

    std::vector<PlacementSlot> first = place(topology, id, 0, policy);
    std::vector<PlacementSlot> second = place(topology, id, 0, policy);

    ASSERT_EQ(first.size(), second.size());
    for (size_t i = 0; i < first.size(); ++i) {
        EXPECT_EQ(first[i].slot_index, second[i].slot_index);
        EXPECT_EQ(rawstd_uuid_cmp(&first[i].ost_id, &second[i].ost_id), 0);
    }
}

TEST(PlacementTest, width_equal_to_domain_count_uses_every_domain) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000002", 100, "host2")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000003", 100, "host3")
    );
    PlacementPolicy policy{3, Level::OST, 1, 0};

    std::vector<PlacementSlot> slots = place(topology, make_id(), 0, policy);

    ASSERT_EQ(slots.size(), 3u);
    std::set<uint8_t> slot_indices;
    std::set<std::string> ost_ids;
    for (const PlacementSlot& slot : slots) {
        slot_indices.insert(slot.slot_index);
        RawstdUUIDString s;
        rawstd_uuid_to_string(&slot.ost_id, &s);
        ost_ids.insert(s);
    }
    // Exactly width slots numbered 0..width-1, one per distinct OST -- no
    // populated domain left unused when width matches the domain count.
    EXPECT_EQ(slot_indices, (std::set<uint8_t>{0, 1, 2}));
    EXPECT_EQ(ost_ids.size(), 3u);
}

TEST(PlacementTest, object_local_stripe_repeats_the_same_placement) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000002", 100, "host2")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000003", 100, "host3")
    );
    RawstdUUID id = make_id();
    // stripe_width 1: object-local -- every chunk of the same object lands
    // on the same OSTs (own doc comment, placement.hpp).
    PlacementPolicy policy{2, Level::OST, 1, 0};

    std::vector<PlacementSlot> chunk0 = place(topology, id, 0, policy);
    std::vector<PlacementSlot> chunk1 = place(topology, id, 1, policy);

    ASSERT_EQ(chunk0.size(), chunk1.size());
    for (size_t i = 0; i < chunk0.size(); ++i) {
        EXPECT_EQ(rawstd_uuid_cmp(&chunk0[i].ost_id, &chunk1[i].ost_id), 0);
    }
}

TEST(PlacementTest, different_objects_can_land_on_different_placements) {
    Topology topology;
    for (int i = 1; i <= 8; ++i) {
        char id[64];
        snprintf(id, sizeof(id), "00000000-0000-7000-8000-%012d", i);
        char host[16];
        snprintf(host, sizeof(host), "host%d", i);
        topology.add(make_ost(id, 100, host));
    }
    PlacementPolicy policy{2, Level::OST, STRIPE_ALL, 0};

    // Sampling a handful of distinct object ids against a topology wide
    // enough to actually vary: not every hash draw is guaranteed to
    // differ, but they can't all coincide by chance across this many
    // draws -- guards against place() degenerating into always picking
    // the same two OSTs regardless of `id`.
    std::set<std::string> distinct_placements;
    for (int i = 0; i < 16; ++i) {
        std::vector<PlacementSlot> slots =
            place(topology, make_id(), 0, policy);
        std::string key;
        for (const PlacementSlot& slot : slots) {
            key.append(
                reinterpret_cast<const char*>(slot.ost_id.bytes),
                sizeof(slot.ost_id.bytes)
            );
        }
        distinct_placements.insert(key);
    }
    EXPECT_GT(distinct_placements.size(), 1u);
}

// Consecutive object ids, as a burst of creates produces: they differ in a
// few low bytes only.
RawstdUUID sequential_id(unsigned i) {
    RawstdUUID id{};
    id.bytes[6] = 0x70;
    id.bytes[8] = 0x80;
    id.bytes[13] = static_cast<uint8_t>(i >> 16);
    id.bytes[14] = static_cast<uint8_t>(i >> 8);
    id.bytes[15] = static_cast<uint8_t>(i);
    return id;
}

std::map<std::string, unsigned>
count_primaries(const Topology& topology, unsigned objects) {
    PlacementPolicy policy{1, Level::OST, STRIPE_ALL, 0};
    std::map<std::string, unsigned> counts;
    for (unsigned i = 0; i < objects; ++i) {
        auto slots = place(topology, sequential_id(i), 0, policy);
        RawstdUUIDString id;
        rawstd_uuid_to_string(&slots.at(0).ost_id, &id);
        ++counts[id];
    }
    return counts;
}

TEST(PlacementTest, spreads_objects_evenly_over_equal_weights) {
    Topology topology;
    for (int i = 1; i <= 8; ++i) {
        char id[64];
        snprintf(id, sizeof(id), "00000000-0000-7000-8000-%012d", i);
        char host[16];
        snprintf(host, sizeof(host), "host%d", i);
        topology.add(make_ost(id, 100, host));
    }
    auto counts = count_primaries(topology, 8000);
    ASSERT_EQ(counts.size(), 8u);
    for (const auto& [ost, count] : counts) {
        EXPECT_GT(count, 850u) << ost;
        EXPECT_LT(count, 1150u) << ost;
    }
}

TEST(PlacementTest, spreads_objects_in_proportion_to_weight) {
    Topology topology;
    topology.add(make_ost("00000000-0000-7000-8000-000000000001", 100, "a"));
    topology.add(make_ost("00000000-0000-7000-8000-000000000002", 300, "b"));
    auto counts = count_primaries(topology, 8000);
    unsigned heavy = counts["00000000-0000-7000-8000-000000000002"];
    EXPECT_GT(heavy, 5760u); // 72%
    EXPECT_LT(heavy, 6240u); // 78%
}

} // namespace

TEST(PlacementTest, even_data_width_adds_one_witness_on_an_unused_domain) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000002", 100, "host2")
    );
    auto mds = make_ost("00000000-0000-7000-8000-000000000003", 100, "host3");
    mds.location = "mds://127.0.0.1:7776";
    topology.add(mds);
    for (uint64_t stripe : {uint64_t(0), uint64_t(1), uint64_t(2)}) {
        PlacementPolicy policy{2, Level::Server, stripe, 7};
        auto id = make_id();
        for (uint64_t index = 0; index < 8; ++index) {
            const auto slots =
                rawstor::mdsserver::place_chunk(topology, id, index, policy);
            ASSERT_EQ(slots.size(), 3u);
            EXPECT_EQ(slots[0].slot_index, 0u);
            EXPECT_EQ(slots[1].slot_index, 1u);
            EXPECT_NE(rawstd_uuid_cmp(&slots[0].ost_id, &mds.id), 0);
            EXPECT_NE(rawstd_uuid_cmp(&slots[1].ost_id, &mds.id), 0);
            EXPECT_EQ(slots[2].slot_index, 2u);
            EXPECT_EQ(rawstd_uuid_cmp(&slots[2].ost_id, &mds.id), 0);
            auto repeat =
                rawstor::mdsserver::place_chunk(topology, id, index, policy);
            for (size_t i = 0; i < slots.size(); ++i) {
                EXPECT_EQ(
                    rawstd_uuid_cmp(&slots[i].ost_id, &repeat[i].ost_id), 0
                );
            }
        }
    }
}

TEST(PlacementTest, witness_can_use_an_ost_and_is_not_added_for_odd_width) {
    Topology topology;
    for (unsigned i = 1; i <= 5; ++i) {
        char uuid[40];
        snprintf(uuid, sizeof(uuid), "00000000-0000-7000-8000-%012u", i);
        topology.add(make_ost(uuid, 100, std::to_string(i).c_str()));
    }
    for (unsigned width : {1u, 2u, 3u, 4u, 5u}) {
        PlacementPolicy policy{width, Level::OST, 0, 0};
        auto slots =
            rawstor::mdsserver::place_chunk(topology, make_id(), 0, policy);
        EXPECT_EQ(slots.size(), width + (width % 2 == 0));
        std::set<std::string> members;
        for (const auto& slot : slots) {
            RawstdUUIDString id;
            rawstd_uuid_to_string(&slot.ost_id, &id);
            EXPECT_TRUE(members.insert(id).second);
        }
    }
}

TEST(PlacementTest, witness_needs_a_distinct_populated_failure_domain) {
    Topology topology;
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000001", 100, "host1")
    );
    topology.add(
        make_ost("00000000-0000-7000-8000-000000000002", 100, "host2")
    );
    auto mds = make_ost("00000000-0000-7000-8000-000000000003", 100, "host1");
    mds.location = "mds://127.0.0.1:7776";
    topology.add(mds);
    EXPECT_THROW(
        rawstor::mdsserver::place_chunk(
            topology, make_id(), 0, PlacementPolicy{2, Level::Server, 0, 0}
        ),
        std::system_error
    );
    EXPECT_EQ(
        rawstor::mdsserver::place_chunk(
            topology, make_id(), 0, PlacementPolicy{2, Level::OST, 0, 0}
        )
            .size(),
        3u
    );
    Topology only_mds;
    only_mds.add(mds);
    EXPECT_THROW(
        rawstor::mdsserver::place_chunk(
            only_mds, make_id(), 0, PlacementPolicy{1, Level::OST, 0, 0}
        ),
        std::system_error
    );
}

TEST(PlacementTest, witness_shares_the_object_pinned_partial_stripe_pool) {
    Topology topology;
    for (unsigned i = 1; i <= 12; ++i) {
        char uuid[40];
        snprintf(uuid, sizeof(uuid), "00000000-0000-7000-8000-%012u", i);
        auto backend = make_ost(uuid, 100, std::to_string(i).c_str());
        if (i > 8) {
            backend.location = "mds://127.0.0.1:7776";
        }
        topology.add(backend);
    }
    auto id = make_id();
    for (uint64_t stripe :
         {uint64_t(1), uint64_t(2), uint64_t(4), uint64_t(6)}) {
        std::set<std::string> domains;
        PlacementPolicy policy{2, Level::Server, stripe, 0};
        for (uint64_t index = 0; index < 64; ++index) {
            const auto slots =
                rawstor::mdsserver::place_chunk(topology, id, index, policy);
            ASSERT_EQ(slots.size(), 3u);
            for (const auto& slot : slots) {
                RawstdUUIDString uuid;
                rawstd_uuid_to_string(&slot.ost_id, &uuid);
                domains.insert(uuid);
            }
        }
        EXPECT_LE(domains.size(), std::max<uint64_t>(stripe, 3));
    }
}
