#include <mds/placement.hpp>
#include <mds/topology.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uuid.h>

#include <set>
#include <string>
#include <vector>

#include <cstdio>

#include <gtest/gtest.h>

namespace {

using rawstor::mds::Level;
using rawstor::mds::place;
using rawstor::mds::PlacementPolicy;
using rawstor::mds::PlacementSlot;
using rawstor::mds::STRIPE_ALL;
using rawstor::mds::Topology;
using rawstor::mds::TopologyOST;

TopologyOST make_ost(const char* id, uint64_t weight, const char* host) {
    TopologyOST ost{};
    if (rawstd_uuid_from_string(&ost.id, id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    ost.location = "ost://127.0.0.1:0";
    ost.weight = weight;
    ost.path[0] = "dc1";
    ost.path[1] = "rack1";
    ost.path[2] = host;
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

} // namespace
