#include "tmp_dir.hpp"

#include <mds/placement.hpp>
#include <mds/store.hpp>
#include <mds/topology.hpp>

#include <rawstor/target.h>

#include <rawstd/gpp.hpp>
#include <rawstd/uuid.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace {

using rawstor::mds::Level;
using rawstor::mds::ObjectDescriptor;
using rawstor::mds::ObjectMap;
using rawstor::mds::ObjectStore;
using rawstor::mds::PlacementPolicy;
using rawstor::mds::ScanRecord;
using rawstor::mds::SnapMember;
using rawstor::mds::STRIPE_ALL;
using rawstor::mds::Topology;
using rawstor::mds::TopologyOST;

constexpr uint64_t chunk_size = 1ull << 16;

TopologyOST make_ost(const char* id, const char* host) {
    TopologyOST ost{};
    if (rawstd_uuid_from_string(&ost.id, id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    ost.address = "127.0.0.1:0";
    ost.weight = 100;
    ost.path[0] = "dc1";
    ost.path[1] = "rack1";
    ost.path[2] = host;
    return ost;
}

// A three-OST topology, one per host, OST-level failure domains -- enough
// to satisfy any policy this file's own tests use (width <= 3).
Topology make_topology() {
    Topology topology;
    topology.add(make_ost("00000000-0000-7000-8000-000000000001", "host1"));
    topology.add(make_ost("00000000-0000-7000-8000-000000000002", "host2"));
    topology.add(make_ost("00000000-0000-7000-8000-000000000003", "host3"));
    return topology;
}

RawstdUUID make_id() {
    RawstdUUID id{};
    if (rawstd_uuid7_init(&id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    return id;
}

PlacementPolicy make_policy(unsigned width) {
    return PlacementPolicy{width, Level::OST, 1, 0};
}

class ObjectStoreTest : public testing::Test {
protected:
    rawstor::mds::tests::TmpDir dir;

    ObjectStore make_store() {
        return ObjectStore(dir.db_path(), make_topology());
    }
};

TEST_F(ObjectStoreTest, create_populates_chunk_map) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    ObjectDescriptor descriptor =
        store.create(id, 3 * chunk_size, chunk_size, make_policy(1));

    EXPECT_EQ(descriptor.logical_size, 3 * chunk_size);
    EXPECT_EQ(descriptor.chunk_size, chunk_size);
    EXPECT_EQ(descriptor.map_epoch, 1u);

    ObjectMap map = store.open(id, RawstdUUID{});
    ASSERT_EQ(map.chunks.size(), 3u);
    for (const auto& slots : map.chunks) {
        EXPECT_EQ(slots.size(), 1u);
    }
}

TEST_F(ObjectStoreTest, create_rejects_duplicate_id) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    store.create(id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(
        store.create(id, chunk_size, chunk_size, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_zero_size) {
    ObjectStore store = make_store();

    EXPECT_THROW(
        store.create(make_id(), 0, chunk_size, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_non_power_of_two_chunk_size) {
    ObjectStore store = make_store();

    EXPECT_THROW(
        store.create(make_id(), chunk_size, 3, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_unsatisfiable_placement) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    // Only 3 OST-level domains exist; width 4 can never be satisfied.
    EXPECT_THROW(
        store.create(id, chunk_size, chunk_size, make_policy(4)),
        std::system_error
    );

    // Nothing landed -- the unsatisfiable check runs before any write
    // (own doc comment, store.cpp: "Hard-fails on an unsatisfiable
    // topology before anything lands").
    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, open_rejects_unknown_id) {
    ObjectStore store = make_store();

    EXPECT_THROW(store.open(make_id(), RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, resize_grows_chunk_count_and_bumps_epoch) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));

    uint64_t map_epoch = store.resize(id, 3 * chunk_size);

    EXPECT_EQ(map_epoch, 2u);
    ObjectMap map = store.open(id, RawstdUUID{});
    EXPECT_EQ(map.descriptor.logical_size, 3 * chunk_size);
    EXPECT_EQ(map.descriptor.map_epoch, 2u);
    ASSERT_EQ(map.chunks.size(), 3u);
    for (const auto& slots : map.chunks) {
        EXPECT_EQ(slots.size(), 1u);
    }
}

TEST_F(ObjectStoreTest, resize_rejects_shrink) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, 3 * chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(store.resize(id, chunk_size), std::system_error);
}

TEST_F(ObjectStoreTest, resize_rejects_zero_size) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(store.resize(id, 0), std::system_error);
}

TEST_F(ObjectStoreTest, remove_deletes_object) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));

    store.remove(id);

    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, remove_rejects_unknown_id) {
    ObjectStore store = make_store();

    EXPECT_THROW(store.remove(make_id()), std::system_error);
}

TEST_F(ObjectStoreTest, remove_rejects_while_snapshot_exists) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));
    RawstdUUID snapshot_id = make_id();
    ObjectMap map = store.open(id, RawstdUUID{});
    std::vector<SnapMember> members;
    for (size_t index = 0; index < map.chunks.size(); ++index) {
        for (const auto& slot : map.chunks[index]) {
            members.push_back(SnapMember{index, slot.ost_id});
        }
    }
    store.snap_commit(id, snapshot_id, members);

    EXPECT_THROW(store.remove(id), std::system_error);

    // Removing the snapshot first clears the way.
    store.snap_remove(id, snapshot_id);
    store.remove(id);
}

TEST_F(ObjectStoreTest, snap_commit_and_open_round_trip) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, 2 * chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID snapshot_id = make_id();

    std::vector<SnapMember> members;
    for (size_t index = 0; index < live.chunks.size(); ++index) {
        for (const auto& slot : live.chunks[index]) {
            members.push_back(SnapMember{index, slot.ost_id});
        }
    }
    uint64_t map_epoch = store.snap_commit(id, snapshot_id, members);
    EXPECT_EQ(map_epoch, 2u);

    ObjectMap snap = store.open(id, snapshot_id);
    EXPECT_EQ(snap.descriptor.logical_size, 2 * chunk_size);
    ASSERT_EQ(snap.chunks.size(), 2u);
    for (size_t index = 0; index < snap.chunks.size(); ++index) {
        ASSERT_EQ(snap.chunks[index].size(), 1u);
        EXPECT_EQ(
            rawstd_uuid_cmp(
                &snap.chunks[index][0].ost_id, &live.chunks[index][0].ost_id
            ),
            0
        );
    }
}

TEST_F(ObjectStoreTest, snap_commit_rejects_nil_snapshot_id) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(store.snap_commit(id, RawstdUUID{}, {}), std::system_error);
}

TEST_F(ObjectStoreTest, snap_commit_rejects_uncovered_chunk) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, 2 * chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});

    // Only chunk 0's own member -- chunk 1 is left uncovered.
    std::vector<SnapMember> members{
        SnapMember{0, live.chunks[0][0].ost_id},
    };

    EXPECT_THROW(store.snap_commit(id, make_id(), members), std::system_error);
}

TEST_F(ObjectStoreTest, snap_commit_freezes_size_across_a_later_resize) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID snapshot_id = make_id();
    store.snap_commit(
        id, snapshot_id, {SnapMember{0, live.chunks[0][0].ost_id}}
    );

    store.resize(id, 3 * chunk_size);

    ObjectMap snap = store.open(id, snapshot_id);
    EXPECT_EQ(snap.descriptor.logical_size, chunk_size);
    EXPECT_EQ(snap.chunks.size(), 1u);
}

TEST_F(ObjectStoreTest, snap_remove_returns_members_and_unregisters) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID snapshot_id = make_id();
    RawstdUUID ost_id = live.chunks[0][0].ost_id;
    store.snap_commit(id, snapshot_id, {SnapMember{0, ost_id}});

    std::vector<SnapMember> removed = store.snap_remove(id, snapshot_id);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0].logical_index, 0u);
    EXPECT_EQ(rawstd_uuid_cmp(&removed[0].ost_id, &ost_id), 0);
    EXPECT_THROW(store.open(id, snapshot_id), std::system_error);
}

TEST_F(ObjectStoreTest, snap_remove_rejects_unknown_snapshot) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(store.snap_remove(id, make_id()), std::system_error);
}

RawstorObjectMeta make_meta(uint64_t size, unsigned width) {
    RawstorObjectMeta meta{};
    meta.spec.size = size;
    meta.spec.width = width;
    meta.spec.chunk_size = chunk_size;
    // member_kind defaults to RAWSTOR_MEMBER_DATA (0) via zero-init.
    return meta;
}

TEST_F(ObjectStoreTest, reconstruct_rebuilds_single_chunk_object) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID ost_id = make_id();

    std::vector<ScanRecord> records{
        ScanRecord{ost_id, id, 0, make_meta(chunk_size, 1)},
    };
    store.reconstruct(records);

    ObjectMap map = store.open(id, RawstdUUID{});
    EXPECT_EQ(map.descriptor.logical_size, chunk_size);
    EXPECT_EQ(map.descriptor.chunk_size, chunk_size);
    EXPECT_EQ(map.descriptor.policy.width, 1u);
    ASSERT_EQ(map.chunks.size(), 1u);
    ASSERT_EQ(map.chunks[0].size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&map.chunks[0][0].ost_id, &ost_id), 0);
}

TEST_F(ObjectStoreTest, reconstruct_rebuilds_multi_chunk_object) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID ost0 = make_id();
    RawstdUUID ost1 = make_id();

    // Chunk 1's own copy is rounded up by its backend past a full
    // chunk_size -- reconstruct() clamps the tail back down to chunk_size
    // (own doc comment, store.cpp).
    std::vector<ScanRecord> records{
        ScanRecord{ost0, id, 0, make_meta(chunk_size, 1)},
        ScanRecord{ost1, id, chunk_size, make_meta(chunk_size + 4096, 1)},
    };
    store.reconstruct(records);

    ObjectMap map = store.open(id, RawstdUUID{});
    EXPECT_EQ(map.descriptor.logical_size, 2 * chunk_size);
    ASSERT_EQ(map.chunks.size(), 2u);
    EXPECT_EQ(rawstd_uuid_cmp(&map.chunks[0][0].ost_id, &ost0), 0);
    EXPECT_EQ(rawstd_uuid_cmp(&map.chunks[1][0].ost_id, &ost1), 0);
}

TEST_F(ObjectStoreTest, reconstruct_skips_witness_records) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstorObjectMeta meta = make_meta(chunk_size, 1);
    meta.member_kind = RAWSTOR_MEMBER_WITNESS;

    std::vector<ScanRecord> records{
        ScanRecord{make_id(), id, 0, meta},
    };
    store.reconstruct(records);

    // A witness-only record contributes no data slot -- the object never
    // gets rebuilt at all.
    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, reconstruct_fails_on_missing_chunk_hole) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    // Chunk 1 (offset chunk_size) never shows up in any record.
    std::vector<ScanRecord> records{
        ScanRecord{make_id(), id, 0, make_meta(chunk_size, 1)},
        ScanRecord{make_id(), id, 2 * chunk_size, make_meta(chunk_size, 1)},
    };

    EXPECT_THROW(store.reconstruct(records), std::system_error);
}

TEST_F(ObjectStoreTest, reconstruct_fails_on_conflicting_identity) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    std::vector<ScanRecord> records{
        ScanRecord{make_id(), id, 0, make_meta(chunk_size, 1)},
        ScanRecord{make_id(), id, 0, make_meta(chunk_size, 2)},
    };

    EXPECT_THROW(store.reconstruct(records), std::system_error);
}

TEST_F(ObjectStoreTest, reconstruct_replaces_every_existing_object) {
    ObjectStore store = make_store();
    RawstdUUID stale_id = make_id();
    store.create(stale_id, chunk_size, chunk_size, make_policy(1));

    RawstdUUID rebuilt_id = make_id();
    std::vector<ScanRecord> records{
        ScanRecord{make_id(), rebuilt_id, 0, make_meta(chunk_size, 1)},
    };
    store.reconstruct(records);

    // reconstruct() replaces every stored object in one transaction (own
    // doc comment, store.hpp) -- an object created before it that isn't
    // among the scanned records is gone.
    EXPECT_THROW(store.open(stale_id, RawstdUUID{}), std::system_error);
    EXPECT_NO_THROW(store.open(rebuilt_id, RawstdUUID{}));
}

} // namespace
