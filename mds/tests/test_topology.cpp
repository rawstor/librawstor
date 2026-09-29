#include <mds/topology.hpp>

#include <rawstd/uuid.h>

#include <sstream>
#include <string>

#include <gtest/gtest.h>

namespace {

using rawstor::mds::Level;
using rawstor::mds::Topology;
using rawstor::mds::TopologyOST;

TEST(TopologyTest, parse_single_ost) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "dc1/rack1/host1\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 1u);
    const TopologyOST& ost = t.osts().front();
    EXPECT_EQ(ost.location, "ost://127.0.0.1:8753");
    EXPECT_EQ(ost.weight, 100u);
    EXPECT_EQ(ost.path[0], "dc1");
    EXPECT_EQ(ost.path[1], "rack1");
    EXPECT_EQ(ost.path[2], "host1");
}

TEST(TopologyTest, parse_skips_comments_and_blank_lines) {
    std::istringstream in(
        "# a comment\n"
        "\n"
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "dc1/rack1/host1 # trailing comment\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 1u);
}

TEST(TopologyTest, parse_multiple_osts) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "dc1/rack1/host1\n"
        "00000000-0000-7000-8000-000000000002 ost://127.0.0.1:8754 100 "
        "dc1/rack1/host2\n"
    );

    Topology t = Topology::parse(in);

    EXPECT_EQ(t.osts().size(), 2u);
}

TEST(TopologyTest, parse_accepts_any_backend_location) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 file:///srv/ost1 100 "
        "dc1/rack1/host1\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 1u);
    EXPECT_EQ(t.osts().front().location, "file:///srv/ost1");
}

TEST(TopologyTest, parse_rejects_multiple_location_uris) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 "
        "ost://127.0.0.1:8753,ost://127.0.0.1:8754 100 dc1/rack1/host1\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

TEST(TopologyTest, parse_rejects_malformed_entry) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

TEST(TopologyTest, parse_rejects_trailing_tokens) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "dc1/rack1/host1 extra\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

TEST(TopologyTest, parse_rejects_malformed_ost_id) {
    std::istringstream in(
        "not-a-uuid ost://127.0.0.1:8753 100 dc1/rack1/host1\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

TEST(TopologyTest, parse_rejects_short_path) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "dc1/rack1\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

TEST(TopologyTest, add_rejects_duplicate_ost_id) {
    Topology t;
    TopologyOST ost{};
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &ost.id, "00000000-0000-7000-8000-000000000001"
        ),
        0
    );
    ost.location = "ost://127.0.0.1:8753";
    ost.weight = 100;
    ost.path[0] = "dc1";
    ost.path[1] = "rack1";
    ost.path[2] = "host1";

    t.add(ost);
    EXPECT_THROW(t.add(ost), std::system_error);
}

TEST(TopologyTest, domain_identity_by_level) {
    TopologyOST ost{};
    ASSERT_EQ(
        rawstd_uuid_from_string(
            &ost.id, "00000000-0000-7000-8000-000000000001"
        ),
        0
    );
    ost.path[0] = "dc1";
    ost.path[1] = "rack1";
    ost.path[2] = "host1";

    EXPECT_EQ(ost.domain(Level::DC), "dc1");
    EXPECT_EQ(ost.domain(Level::Rack), "dc1/rack1");
    EXPECT_EQ(ost.domain(Level::Server), "dc1/rack1/host1");
    // OST is the degenerate per-leaf domain: its own id disambiguates it
    // from another OST on the very same host (own doc comment,
    // topology.hpp).
    EXPECT_EQ(
        ost.domain(Level::OST),
        "dc1/rack1/host1/00000000-0000-7000-8000-000000000001"
    );
}

TEST(TopologyTest, domain_identity_uses_full_path_not_last_component) {
    // Two "host1" in different racks are different domains (own doc
    // comment, topology.hpp) -- the full path prefix, not the leaf name
    // alone, is what makes a domain's identity.
    TopologyOST a{};
    a.path[0] = "dc1";
    a.path[1] = "rack1";
    a.path[2] = "host1";
    TopologyOST b{};
    b.path[0] = "dc1";
    b.path[1] = "rack2";
    b.path[2] = "host1";

    EXPECT_NE(a.domain(Level::Server), b.domain(Level::Server));
}

} // namespace
