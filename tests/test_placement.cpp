#include "placement.hpp"
#include "topology.hpp"

#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <set>
#include <sstream>
#include <string>
#include <system_error>

namespace {

using rawstor::mds::Level;
using rawstor::mds::PlacementPolicy;
using rawstor::mds::PlacementSlot;
using rawstor::mds::STRIPE_ALL;
using rawstor::mds::Topology;
using rawstor::mds::TopologyOST;

RawstdUUID uuid(const std::string& s) {
    RawstdUUID ret;
    EXPECT_EQ(rawstd_uuid_from_string(&ret, s.c_str()), 0);
    return ret;
}

std::string ost_uuid(unsigned n) {
    char buf[64];
    snprintf(buf, sizeof(buf), "00000000-0000-7000-8000-%012x", n);
    return buf;
}

/* 2 dcs x 2 racks x 2 hosts, one OST each, weight 100. */
Topology topology_2x2x2() {
    std::ostringstream oss;
    unsigned n = 1;
    for (int dc = 1; dc <= 2; ++dc) {
        for (int rack = 1; rack <= 2; ++rack) {
            for (int host = 1; host <= 2; ++host) {
                oss << "ost " << ost_uuid(n) << " 127.0.0.1:" << (8752 + n)
                    << " 100 dc" << dc << "/rack" << rack << "/host" << dc
                    << rack << host << "\n";
                ++n;
            }
        }
    }
    std::istringstream in(oss.str());
    return Topology::parse(in);
}

std::string domain_of(const Topology& t, const RawstdUUID& id, Level level) {
    for (const TopologyOST& ost : t.osts()) {
        if (memcmp(ost.id.bytes, id.bytes, sizeof(id.bytes)) == 0) {
            return ost.domain(level);
        }
    }
    ADD_FAILURE() << "ost not in topology";
    return {};
}

TEST(TopologyTest, parse_and_reject_malformed) {
    Topology t = topology_2x2x2();
    EXPECT_EQ(t.osts().size(), 8u);
    EXPECT_EQ(t.osts()[0].weight, 100u);
    EXPECT_EQ(t.osts()[0].path[0], "dc1");
    EXPECT_EQ(t.osts()[0].domain(Level::Rack), "dc1/rack1");

    {
        std::istringstream in("# comment only\n\n");
        EXPECT_EQ(Topology::parse(in).osts().size(), 0u);
    }
    {
        std::istringstream in("volume x\n");
        EXPECT_THROW(Topology::parse(in), std::system_error);
    }
    {
        std::istringstream in(
            "ost 00000000-0000-7000-8000-000000000001 127.0.0.1:1 100 dc1\n"
        );
        EXPECT_THROW(Topology::parse(in), std::system_error);
    }
    {
        std::istringstream in(
            "ost not-a-uuid 127.0.0.1:1 100 dc1/rack1/host1\n"
        );
        EXPECT_THROW(Topology::parse(in), std::system_error);
    }
    {
        /* duplicate id */
        std::ostringstream oss;
        oss << "ost " << ost_uuid(1) << " 127.0.0.1:1 100 dc1/rack1/host1\n"
            << "ost " << ost_uuid(1) << " 127.0.0.1:2 100 dc1/rack1/host2\n";
        std::istringstream in(oss.str());
        EXPECT_THROW(Topology::parse(in), std::system_error);
    }
}

TEST(PlacementTest, deterministic) {
    Topology t = topology_2x2x2();
    PlacementPolicy policy{2, Level::Rack, STRIPE_ALL, 42};
    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000000");

    for (uint64_t index = 0; index < 16; ++index) {
        std::vector<PlacementSlot> a = place(t, vol, index, policy);
        std::vector<PlacementSlot> b = place(t, vol, index, policy);
        ASSERT_EQ(a.size(), 2u);
        for (size_t i = 0; i < a.size(); ++i) {
            EXPECT_EQ(a[i].slot_index, b[i].slot_index);
            EXPECT_EQ(
                memcmp(
                    a[i].ost_id.bytes, b[i].ost_id.bytes,
                    sizeof(a[i].ost_id.bytes)
                ),
                0
            );
        }
    }
}

TEST(PlacementTest, slots_in_distinct_failure_domains) {
    Topology t = topology_2x2x2();
    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000001");

    for (Level level : {Level::DC, Level::Rack, Level::Server, Level::OST}) {
        PlacementPolicy policy{2, level, STRIPE_ALL, 7};
        for (uint64_t index = 0; index < 64; ++index) {
            std::vector<PlacementSlot> slots = place(t, vol, index, policy);
            ASSERT_EQ(slots.size(), 2u);
            EXPECT_NE(
                domain_of(t, slots[0].ost_id, level),
                domain_of(t, slots[1].ost_id, level)
            ) << "level "
              << static_cast<unsigned>(level) << " index " << index;
        }
    }
}

TEST(PlacementTest, unsatisfiable_topology_hard_fails) {
    Topology t = topology_2x2x2();
    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000002");

    /* 3 copies over 2 dcs is unsatisfiable at the dc level. */
    PlacementPolicy policy{3, Level::DC, STRIPE_ALL, 7};
    EXPECT_THROW(place(t, vol, 0, policy), std::system_error);

    /* ...but satisfiable one level down. */
    policy.failure_domain = Level::Rack;
    EXPECT_EQ(place(t, vol, 0, policy).size(), 3u);
}

TEST(PlacementTest, stripe_width_one_pins_the_volume) {
    Topology t = topology_2x2x2();
    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000003");
    PlacementPolicy policy{2, Level::Server, 1, 7};

    std::vector<PlacementSlot> first = place(t, vol, 0, policy);
    for (uint64_t index = 1; index < 64; ++index) {
        std::vector<PlacementSlot> slots = place(t, vol, index, policy);
        ASSERT_EQ(slots.size(), first.size());
        for (size_t i = 0; i < slots.size(); ++i) {
            EXPECT_EQ(
                memcmp(
                    slots[i].ost_id.bytes, first[i].ost_id.bytes,
                    sizeof(first[i].ost_id.bytes)
                ),
                0
            ) << "index "
              << index << " slot " << i;
        }
    }
}

TEST(PlacementTest, stripe_all_spreads_chunks) {
    Topology t = topology_2x2x2();
    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000004");
    PlacementPolicy policy{2, Level::Server, STRIPE_ALL, 7};

    std::set<std::string> primaries;
    for (uint64_t index = 0; index < 64; ++index) {
        std::vector<PlacementSlot> slots = place(t, vol, index, policy);
        RawstdUUIDString s;
        rawstd_uuid_to_string(&slots[0].ost_id, &s);
        primaries.insert(s);
    }
    /* 64 chunks over 8 OSTs: more than one distinct primary. */
    EXPECT_GT(primaries.size(), 1u);
}

TEST(PlacementTest, partial_stripe_stays_within_the_pool) {
    Topology t = topology_2x2x2();
    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000005");

    /* Pool of 4 server domains out of 8. */
    PlacementPolicy policy{2, Level::Server, 4, 7};

    std::set<std::string> domains;
    for (uint64_t index = 0; index < 256; ++index) {
        for (const PlacementSlot& slot : place(t, vol, index, policy)) {
            domains.insert(domain_of(t, slot.ost_id, Level::Server));
        }
    }
    EXPECT_LE(domains.size(), 4u);
    EXPECT_GT(domains.size(), 1u);
}

TEST(PlacementTest, zero_weight_ost_is_never_chosen) {
    std::ostringstream oss;
    oss << "ost " << ost_uuid(1) << " 127.0.0.1:1 100 dc1/rack1/host1\n"
        << "ost " << ost_uuid(2) << " 127.0.0.1:2 0 dc1/rack1/host1\n"
        << "ost " << ost_uuid(3) << " 127.0.0.1:3 100 dc1/rack2/host2\n";
    std::istringstream in(oss.str());
    Topology t = Topology::parse(in);

    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000006");
    RawstdUUID dead = uuid(ost_uuid(2));
    PlacementPolicy policy{2, Level::Rack, STRIPE_ALL, 7};

    for (uint64_t index = 0; index < 64; ++index) {
        for (const PlacementSlot& slot : place(t, vol, index, policy)) {
            EXPECT_NE(
                memcmp(slot.ost_id.bytes, dead.bytes, sizeof(dead.bytes)), 0
            );
        }
    }
}

TEST(PlacementTest, minimal_reshuffle_on_topology_growth) {
    Topology before = topology_2x2x2();

    Topology after = topology_2x2x2();
    TopologyOST extra{};
    EXPECT_EQ(rawstd_uuid_from_string(&extra.id, ost_uuid(9).c_str()), 0);
    extra.address = "127.0.0.1:8761";
    extra.weight = 100;
    extra.path[0] = "dc1";
    extra.path[1] = "rack1";
    extra.path[2] = "host119";
    after.add(extra);

    RawstdUUID vol = uuid("11111111-0000-7000-8000-000000000007");
    PlacementPolicy policy{2, Level::Server, STRIPE_ALL, 7};

    unsigned moved = 0;
    const unsigned chunks = 256;
    for (uint64_t index = 0; index < chunks; ++index) {
        std::vector<PlacementSlot> a = place(before, vol, index, policy);
        std::vector<PlacementSlot> b = place(after, vol, index, policy);
        for (size_t i = 0; i < a.size(); ++i) {
            if (memcmp(
                    a[i].ost_id.bytes, b[i].ost_id.bytes,
                    sizeof(a[i].ost_id.bytes)
                ) != 0) {
                ++moved;
            }
        }
    }

    /*
     * One of nine equal-weight servers was added: the rendezvous property
     * bounds the expected movement to roughly 1/9 of the slots. Allow
     * generous slack, but far below a full reshuffle.
     */
    EXPECT_LT(moved, chunks / 2);
    EXPECT_GT(moved, 0u);
}

} // unnamed namespace
