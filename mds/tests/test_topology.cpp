#include <mds/topology.hpp>

#include "ost_registration.hpp"

#include <rawstd/uuid.h>

#include <string>
#include <system_error>

#include <gtest/gtest.h>

namespace {

using rawstor::mdsserver::Level;
using rawstor::mdsserver::Topology;
using rawstor::mdsserver::TopologyOST;

TopologyOST ost_in(const char* id, const char* domain) {
    TopologyOST ost{};
    EXPECT_EQ(rawstd_uuid_from_string(&ost.id, id), 0);
    rawstor::split_domain(domain, ost.path);
    return ost;
}

} // namespace

// The path goes root first and only the server is required: a level an
// entry leaves out is one implicit domain shared by every entry that
// leaves it out too.
TEST(TopologyTest, a_domain_may_leave_out_its_head) {
    TopologyOST a =
        ost_in("00000000-0000-7000-8000-000000000001", "rack1/host1");
    TopologyOST b =
        ost_in("00000000-0000-7000-8000-000000000002", "rack2/host2");
    TopologyOST c = ost_in("00000000-0000-7000-8000-000000000003", "host3");

    EXPECT_EQ(a.path[3], "host1");
    EXPECT_EQ(a.path[2], "rack1");
    EXPECT_EQ(a.path[1], "");
    EXPECT_EQ(a.path[0], "");
    // No row/dc given anywhere: one shared row and dc.
    EXPECT_EQ(a.domain(Level::DC), b.domain(Level::DC));
    EXPECT_EQ(a.domain(Level::Row), b.domain(Level::Row));
    EXPECT_NE(a.domain(Level::Rack), b.domain(Level::Rack));
    // No rack given for c: its own implicit rack, not a's or b's.
    EXPECT_NE(c.domain(Level::Rack), a.domain(Level::Rack));
    EXPECT_NE(c.domain(Level::Rack), b.domain(Level::Rack));
}

TEST(TopologyTest, a_malformed_domain_is_rejected) {
    for (const char* domain :
         {"", "row1//host1", "region1/dc1/row1/rack1/host1", "/rack1",
          "host1/"}) {
        std::string path[4];
        EXPECT_THROW(rawstor::split_domain(domain, path), std::system_error)
            << domain;
    }
}

TEST(TopologyTest, add_rejects_duplicate_ost_id) {
    Topology t;
    TopologyOST ost =
        ost_in("00000000-0000-7000-8000-000000000001", "dc1/row1/rack1/host1");
    ost.location = "ost://127.0.0.1:8753";
    ost.weight = 100;

    t.add(ost);
    EXPECT_THROW(t.add(ost), std::system_error);
}

TEST(TopologyTest, add_rejects_an_entry_without_a_role) {
    Topology t;
    TopologyOST ost =
        ost_in("00000000-0000-7000-8000-000000000001", "dc1/row1/rack1/host1");
    ost.roles.clear();
    EXPECT_THROW(t.add(ost), std::system_error);
}

TEST(TopologyTest, domain_identity_by_level) {
    TopologyOST ost =
        ost_in("00000000-0000-7000-8000-000000000001", "dc1/row1/rack1/host1");

    EXPECT_EQ(ost.domain(Level::DC), "dc1");
    EXPECT_EQ(ost.domain(Level::Row), "dc1/row1");
    EXPECT_EQ(ost.domain(Level::Rack), "dc1/row1/rack1");
    EXPECT_EQ(ost.domain(Level::Server), "dc1/row1/rack1/host1");
    // OST is the degenerate per-leaf domain: its own id disambiguates it
    // from another OST on the very same host (own doc comment,
    // topology.hpp).
    EXPECT_EQ(
        ost.domain(Level::OST),
        "dc1/row1/rack1/host1/00000000-0000-7000-8000-000000000001"
    );
}

TEST(TopologyTest, domain_identity_uses_full_path_not_last_component) {
    // Two "host1" in different racks are different domains (own doc
    // comment, topology.hpp) -- the full path prefix, not the leaf name
    // alone, is what makes a domain's identity.
    TopologyOST a =
        ost_in("00000000-0000-7000-8000-000000000001", "dc1/row1/rack1/host1");
    TopologyOST b =
        ost_in("00000000-0000-7000-8000-000000000002", "dc1/row1/rack2/host1");

    EXPECT_NE(a.domain(Level::Server), b.domain(Level::Server));
}

// 0 is RAWSTOR_OBJ_DOMAIN_DEFAULT, which the client resolves before it
// ever reaches the MDS; anything past DC is not a level (yet).
TEST(TopologyTest, level_of_rejects_default_and_unknown_levels) {
    EXPECT_EQ(rawstor::mdsserver::level_of(1), Level::OST);
    EXPECT_EQ(rawstor::mdsserver::level_of(5), Level::DC);
    EXPECT_THROW(rawstor::mdsserver::level_of(0), std::system_error);
    EXPECT_THROW(rawstor::mdsserver::level_of(6), std::system_error);
}
