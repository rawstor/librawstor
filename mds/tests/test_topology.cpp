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
        "host1/rack1/row1/dc1\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 1u);
    const TopologyOST& ost = t.osts().front();
    EXPECT_EQ(ost.location, "ost://127.0.0.1:8753");
    EXPECT_EQ(ost.weight, 100u);
    EXPECT_EQ(ost.path[0], "dc1");
    EXPECT_EQ(ost.path[1], "row1");
    EXPECT_EQ(ost.path[2], "rack1");
    EXPECT_EQ(ost.path[3], "host1");
}

TEST(TopologyTest, parse_skips_comments_and_blank_lines) {
    std::istringstream in(
        "# a comment\n"
        "\n"
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "host1/rack1/row1/dc1 # trailing comment\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 1u);
}

TEST(TopologyTest, parse_multiple_osts) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "host1/rack1/row1/dc1\n"
        "00000000-0000-7000-8000-000000000002 ost://127.0.0.1:8754 100 "
        "host2/rack1/row1/dc1\n"
    );

    Topology t = Topology::parse(in);

    EXPECT_EQ(t.osts().size(), 2u);
}

TEST(TopologyTest, parse_accepts_any_backend_location) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 file:///srv/ost1 100 "
        "host1/rack1/row1/dc1\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 1u);
    EXPECT_EQ(t.osts().front().location, "file:///srv/ost1");
}

TEST(TopologyTest, parse_rejects_multiple_location_uris) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 "
        "ost://127.0.0.1:8753,ost://127.0.0.1:8754 100 host1/rack1/row1/dc1\n"
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
        "host1/rack1/row1/dc1 extra\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

TEST(TopologyTest, parse_rejects_malformed_ost_id) {
    std::istringstream in(
        "not-a-uuid ost://127.0.0.1:8753 100 host1/rack1/row1/dc1\n"
    );

    EXPECT_THROW(Topology::parse(in), std::system_error);
}

// The path goes leaf first and only the server is required: a level an
// entry leaves out is one implicit domain shared by every entry that
// leaves it out too.
TEST(TopologyTest, parse_accepts_path_without_tail) {
    std::istringstream in(
        "00000000-0000-7000-8000-000000000001 ost://127.0.0.1:8753 100 "
        "host1/rack1\n"
        "00000000-0000-7000-8000-000000000002 ost://127.0.0.1:8754 100 "
        "host2/rack2\n"
        "00000000-0000-7000-8000-000000000003 ost://127.0.0.1:8755 100 "
        "host3\n"
    );

    Topology t = Topology::parse(in);

    ASSERT_EQ(t.osts().size(), 3u);
    const TopologyOST& a = t.osts()[0];
    const TopologyOST& b = t.osts()[1];
    const TopologyOST& c = t.osts()[2];
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

TEST(TopologyTest, parse_rejects_malformed_path) {
    for (const char* path :
         {"host1//row1", "host1/rack1/row1/dc1/region1", "/rack1", "host1/"}) {
        std::istringstream in(
            std::string(
                "00000000-0000-7000-8000-000000000001 "
                "ost://127.0.0.1:8753 100 "
            ) +
            path + "\n"
        );
        EXPECT_THROW(Topology::parse(in), std::system_error) << path;
    }
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
    ost.path[1] = "row1";
    ost.path[2] = "rack1";
    ost.path[3] = "host1";

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
    ost.path[1] = "row1";
    ost.path[2] = "rack1";
    ost.path[3] = "host1";

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
    TopologyOST a{};
    a.path[0] = "dc1";
    a.path[1] = "row1";
    a.path[2] = "rack1";
    a.path[3] = "host1";
    TopologyOST b{};
    b.path[0] = "dc1";
    b.path[1] = "row1";
    b.path[2] = "rack2";
    b.path[3] = "host1";

    EXPECT_NE(a.domain(Level::Server), b.domain(Level::Server));
}

// 0 is RAWSTOR_OBJ_DOMAIN_DEFAULT, which the client resolves before it
// ever reaches the MDS; anything past DC is not a level (yet).
TEST(TopologyTest, level_of_rejects_default_and_unknown_levels) {
    EXPECT_EQ(rawstor::mds::level_of(1), Level::OST);
    EXPECT_EQ(rawstor::mds::level_of(5), Level::DC);
    EXPECT_THROW(rawstor::mds::level_of(0), std::system_error);
    EXPECT_THROW(rawstor::mds::level_of(6), std::system_error);
}

} // namespace
