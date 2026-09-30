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

using rawstor::mdsserver::Level;
using rawstor::mdsserver::ObjectDescriptor;
using rawstor::mdsserver::ObjectMap;
using rawstor::mdsserver::ObjectStore;
using rawstor::mdsserver::PlacementPolicy;
using rawstor::mdsserver::ResizeResult;
using rawstor::mdsserver::ScanRecord;
using rawstor::mdsserver::SnapshotMember;
using rawstor::mdsserver::STRIPE_ALL;
using rawstor::mdsserver::Topology;
using rawstor::mdsserver::TopologyOST;

constexpr uint64_t chunk_size = 1ull << 16;

TopologyOST make_ost(const char* id, const char* host) {
    TopologyOST ost{};
    if (rawstd_uuid_from_string(&ost.id, id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    ost.location = "ost://127.0.0.1:0";
    ost.weight = 100;
    ost.path[0] = "dc1";
    ost.path[1] = "row1";
    ost.path[2] = "rack1";
    ost.path[3] = host;
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
    rawstor::mdsserver::tests::TmpDir dir;

    ObjectStore make_store() {
        return ObjectStore(dir.db_path(), make_topology());
    }
};

TEST_F(ObjectStoreTest, create_populates_chunk_map) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    ObjectDescriptor descriptor = store.create(
        RawstdUUID{}, id, 3 * chunk_size, chunk_size, make_policy(1)
    );

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

    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(
        store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_zero_size) {
    ObjectStore store = make_store();

    EXPECT_THROW(
        store.create(RawstdUUID{}, make_id(), 0, chunk_size, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_non_power_of_two_chunk_size) {
    ObjectStore store = make_store();

    EXPECT_THROW(
        store.create(RawstdUUID{}, make_id(), chunk_size, 3, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_size_not_chunk_multiple) {
    ObjectStore store = make_store();

    EXPECT_THROW(
        store.create(
            RawstdUUID{}, make_id(), chunk_size + 4096, chunk_size,
            make_policy(1)
        ),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_unsatisfiable_placement) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();

    // Only 3 OST-level domains exist; width 4 can never be satisfied.
    EXPECT_THROW(
        store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(4)),
        std::system_error
    );

    // Nothing landed -- the unsatisfiable check runs before any write
    // (own doc comment, store.cpp: "Hard-fails on an unsatisfiable
    // topology before anything lands").
    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, set_topology_adds_ost) {
    ObjectStore store = make_store();
    store.create(
        RawstdUUID{}, make_id(), chunk_size, chunk_size, make_policy(3)
    );

    Topology topology = make_topology();
    topology.add(make_ost("00000000-0000-7000-8000-000000000004", "host4"));
    store.set_topology(std::move(topology));

    EXPECT_EQ(store.topology()->osts().size(), 4u);
}

TEST_F(ObjectStoreTest, set_topology_refuses_dropping_ost_with_chunks) {
    ObjectStore store = make_store();
    // Width 3 of 3 OSTs: every OST holds a copy.
    store.create(
        RawstdUUID{}, make_id(), chunk_size, chunk_size, make_policy(3)
    );

    Topology topology;
    topology.add(make_ost("00000000-0000-7000-8000-000000000001", "host1"));
    topology.add(make_ost("00000000-0000-7000-8000-000000000002", "host2"));

    try {
        store.set_topology(std::move(topology));
        FAIL() << "expected EBUSY";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EBUSY);
    }
    EXPECT_EQ(store.topology()->osts().size(), 3u);
    EXPECT_THROW(store.check_topology(Topology()), std::system_error);
}

TEST_F(ObjectStoreTest, set_topology_allows_dropping_unused_ost) {
    ObjectStore store = make_store();

    Topology topology;
    topology.add(make_ost("00000000-0000-7000-8000-000000000001", "host1"));
    store.set_topology(std::move(topology));

    EXPECT_EQ(store.topology()->osts().size(), 1u);
}

// Idempotent mutations (docs/mds.md): a repeated idempotency_key replays the
// first call's result instead of applying anything again.
TEST_F(ObjectStoreTest, create_replays_repeated_idempotency_key) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();

    ObjectDescriptor first = store.create(
        idempotency_key, id, chunk_size, chunk_size, make_policy(1)
    );
    ObjectDescriptor again = store.create(
        idempotency_key, id, chunk_size, chunk_size, make_policy(1)
    );
    EXPECT_EQ(again.map_epoch, first.map_epoch);

    // A different op for the same id is a genuine second create.
    EXPECT_THROW(
        store.create(make_id(), id, chunk_size, chunk_size, make_policy(1)),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_replayed_after_rollback_creates_afresh) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();

    store.create(idempotency_key, id, chunk_size, chunk_size, make_policy(1));
    store.remove(make_id(), id);

    store.create(idempotency_key, id, chunk_size, chunk_size, make_policy(1));
    EXPECT_NO_THROW(store.open(id, RawstdUUID{}));
}

TEST_F(ObjectStoreTest, resize_replays_repeated_idempotency_key) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    ResizeResult first = store.resize(idempotency_key, id, 3 * chunk_size);
    ResizeResult again = store.resize(idempotency_key, id, 3 * chunk_size);

    EXPECT_EQ(first.old_nchunks, 1u);
    EXPECT_EQ(again.old_nchunks, 1u);
    EXPECT_EQ(again.map_epoch, first.map_epoch);
    EXPECT_EQ(
        store.open(id, RawstdUUID{}).descriptor.map_epoch, first.map_epoch
    );
}

TEST_F(ObjectStoreTest, remove_replays_the_removed_map) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();
    store.create(RawstdUUID{}, id, 2 * chunk_size, chunk_size, make_policy(1));

    ObjectMap first = store.remove(idempotency_key, id);
    ObjectMap again = store.remove(idempotency_key, id);

    ASSERT_EQ(first.chunks.size(), 2u);
    ASSERT_EQ(again.chunks.size(), 2u);
    for (size_t i = 0; i < 2; ++i) {
        ASSERT_EQ(again.chunks[i].size(), first.chunks[i].size());
        EXPECT_EQ(
            rawstd_uuid_cmp(
                &again.chunks[i][0].ost_id, &first.chunks[i][0].ost_id
            ),
            0
        );
    }
    EXPECT_EQ(again.descriptor.logical_size, 2 * chunk_size);

    // Without the idempotency_key it's a plain remove of a missing object.
    EXPECT_THROW(store.remove(make_id(), id), std::system_error);
}

TEST_F(ObjectStoreTest, snapshots_replay_repeated_idempotency_key) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID snapshot_id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));
    ObjectMap map = store.open(id, RawstdUUID{});
    std::vector<SnapshotMember> members{{0, map.chunks[0][0].ost_id}};

    RawstdUUID commit_op = make_id();
    uint64_t first = store.commit_snapshot(commit_op, id, snapshot_id, members);
    EXPECT_EQ(
        store.commit_snapshot(commit_op, id, snapshot_id, members), first
    );

    RawstdUUID remove_op = make_id();
    std::vector<SnapshotMember> removed =
        store.remove_snapshot(remove_op, id, snapshot_id);
    std::vector<SnapshotMember> again =
        store.remove_snapshot(remove_op, id, snapshot_id);
    ASSERT_EQ(removed.size(), 1u);
    ASSERT_EQ(again.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&again[0].ost_id, &removed[0].ost_id), 0);
}

TEST_F(ObjectStoreTest, idempotency_key_reused_for_another_call_is_einval) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();
    store.create(idempotency_key, id, chunk_size, chunk_size, make_policy(1));

    try {
        store.resize(idempotency_key, id, 2 * chunk_size);
        FAIL() << "expected EINVAL";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EINVAL);
    }
}

TEST_F(ObjectStoreTest, open_rejects_unknown_id) {
    ObjectStore store = make_store();

    EXPECT_THROW(store.open(make_id(), RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, resize_grows_chunk_count_and_bumps_epoch) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    uint64_t map_epoch =
        store.resize(RawstdUUID{}, id, 3 * chunk_size).map_epoch;

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
    store.create(RawstdUUID{}, id, 3 * chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(store.resize(RawstdUUID{}, id, chunk_size), std::system_error);
}

TEST_F(ObjectStoreTest, resize_rejects_size_not_chunk_multiple) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(
        store.resize(RawstdUUID{}, id, 2 * chunk_size + 4096), std::system_error
    );

    ObjectMap map = store.open(id, RawstdUUID{});
    EXPECT_EQ(map.descriptor.logical_size, chunk_size);
    EXPECT_EQ(map.descriptor.map_epoch, 1u);
}

TEST_F(ObjectStoreTest, resize_rejects_zero_size) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(store.resize(RawstdUUID{}, id, 0), std::system_error);
}

TEST_F(ObjectStoreTest, remove_deletes_object) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    store.remove(RawstdUUID{}, id);

    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, remove_rejects_unknown_id) {
    ObjectStore store = make_store();

    EXPECT_THROW(store.remove(RawstdUUID{}, make_id()), std::system_error);
}

TEST_F(ObjectStoreTest, remove_rejects_while_snapshot_exists) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));
    RawstdUUID snapshot_id = make_id();
    ObjectMap map = store.open(id, RawstdUUID{});
    std::vector<SnapshotMember> members;
    for (size_t index = 0; index < map.chunks.size(); ++index) {
        for (const auto& slot : map.chunks[index]) {
            members.push_back(SnapshotMember{index, slot.ost_id});
        }
    }
    store.commit_snapshot(RawstdUUID{}, id, snapshot_id, members);

    EXPECT_THROW(store.remove(RawstdUUID{}, id), std::system_error);

    // Removing the snapshot first clears the way.
    store.remove_snapshot(RawstdUUID{}, id, snapshot_id);
    store.remove(RawstdUUID{}, id);
}

TEST_F(ObjectStoreTest, commit_snapshot_and_open_round_trip) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, 2 * chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID snapshot_id = make_id();

    std::vector<SnapshotMember> members;
    for (size_t index = 0; index < live.chunks.size(); ++index) {
        for (const auto& slot : live.chunks[index]) {
            members.push_back(SnapshotMember{index, slot.ost_id});
        }
    }
    uint64_t map_epoch =
        store.commit_snapshot(RawstdUUID{}, id, snapshot_id, members);
    EXPECT_EQ(map_epoch, 2u);

    ObjectMap snapshot_map = store.open(id, snapshot_id);
    EXPECT_EQ(snapshot_map.descriptor.logical_size, 2 * chunk_size);
    ASSERT_EQ(snapshot_map.chunks.size(), 2u);
    for (size_t index = 0; index < snapshot_map.chunks.size(); ++index) {
        ASSERT_EQ(snapshot_map.chunks[index].size(), 1u);
        EXPECT_EQ(
            rawstd_uuid_cmp(
                &snapshot_map.chunks[index][0].ost_id,
                &live.chunks[index][0].ost_id
            ),
            0
        );
    }
}

TEST_F(ObjectStoreTest, list_objects_pages_by_id) {
    ObjectStore store = make_store();
    std::vector<RawstdUUID> ids = {make_id(), make_id(), make_id()};
    for (const RawstdUUID& id : ids) {
        store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));
    }

    bool more = true;
    std::vector<RawstdUUID> page = store.list_objects(RawstdUUID{}, 2, &more);
    ASSERT_EQ(page.size(), 2u);
    EXPECT_TRUE(more);
    EXPECT_EQ(rawstd_uuid_cmp(&page[0], &ids[0]), 0);
    EXPECT_EQ(rawstd_uuid_cmp(&page[1], &ids[1]), 0);

    page = store.list_objects(page.back(), 2, &more);
    ASSERT_EQ(page.size(), 1u);
    EXPECT_FALSE(more);
    EXPECT_EQ(rawstd_uuid_cmp(&page[0], &ids[2]), 0);
}

TEST_F(ObjectStoreTest, list_snapshots_oldest_first) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    std::vector<SnapshotMember> members;
    for (const auto& slot : live.chunks[0]) {
        members.push_back(SnapshotMember{0, slot.ost_id});
    }

    EXPECT_TRUE(store.list_snapshots(id).empty());

    RawstdUUID first = make_id();
    RawstdUUID second = make_id();
    // Committed newest first: the listing still comes back oldest first.
    store.commit_snapshot(RawstdUUID{}, id, second, members);
    store.commit_snapshot(RawstdUUID{}, id, first, members);

    std::vector<RawstdUUID> snapshots = store.list_snapshots(id);
    ASSERT_EQ(snapshots.size(), 2u);
    EXPECT_EQ(rawstd_uuid_cmp(&snapshots[0], &first), 0);
    EXPECT_EQ(rawstd_uuid_cmp(&snapshots[1], &second), 0);

    try {
        store.list_snapshots(make_id());
        ADD_FAILURE() << "list_snapshots() of an unknown object succeeded";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOENT);
    }
}

TEST_F(ObjectStoreTest, commit_snapshot_rejects_nil_snapshot_id) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(
        store.commit_snapshot(RawstdUUID{}, id, RawstdUUID{}, {}),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, commit_snapshot_rejects_uncovered_chunk) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, 2 * chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});

    // Only chunk 0's own member -- chunk 1 is left uncovered.
    std::vector<SnapshotMember> members{
        SnapshotMember{0, live.chunks[0][0].ost_id},
    };

    EXPECT_THROW(
        store.commit_snapshot(RawstdUUID{}, id, make_id(), members),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, commit_snapshot_freezes_size_across_a_later_resize) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID snapshot_id = make_id();
    store.commit_snapshot(
        RawstdUUID{}, id, snapshot_id,
        {SnapshotMember{0, live.chunks[0][0].ost_id}}
    );

    store.resize(RawstdUUID{}, id, 3 * chunk_size);

    ObjectMap snapshot_map = store.open(id, snapshot_id);
    EXPECT_EQ(snapshot_map.descriptor.logical_size, chunk_size);
    EXPECT_EQ(snapshot_map.chunks.size(), 1u);
}

TEST_F(ObjectStoreTest, remove_snapshot_returns_members_and_unregisters) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID snapshot_id = make_id();
    RawstdUUID ost_id = live.chunks[0][0].ost_id;
    store.commit_snapshot(
        RawstdUUID{}, id, snapshot_id, {SnapshotMember{0, ost_id}}
    );

    std::vector<SnapshotMember> removed =
        store.remove_snapshot(RawstdUUID{}, id, snapshot_id);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0].logical_index, 0u);
    EXPECT_EQ(rawstd_uuid_cmp(&removed[0].ost_id, &ost_id), 0);
    EXPECT_THROW(store.open(id, snapshot_id), std::system_error);
}

TEST_F(ObjectStoreTest, remove_snapshot_rejects_unknown_snapshot) {
    ObjectStore store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1));

    EXPECT_THROW(
        store.remove_snapshot(RawstdUUID{}, id, make_id()), std::system_error
    );
}

RawstorObjectMeta make_meta(uint64_t size, unsigned width) {
    RawstorObjectMeta meta{};
    meta.spec.size = size;
    meta.spec.width = width;
    meta.spec.chunk_size = chunk_size;
    // member_role defaults to RAWSTOR_MEMBER_DATA (0) via zero-init.
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
    // chunk_size -- the object's size comes from the chunk count alone,
    // not from any copy's own size.
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
    meta.member_role = RAWSTOR_MEMBER_WITNESS;

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
    store.create(
        RawstdUUID{}, stale_id, chunk_size, chunk_size, make_policy(1)
    );

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
