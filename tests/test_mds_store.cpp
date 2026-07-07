#include "store.hpp"

#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <filesystem>
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
using rawstor::mds::VolumeDescriptor;
using rawstor::mds::VolumeMap;
using rawstor::mds::VolumeStore;

Topology topology_4_hosts() {
    std::ostringstream oss;
    for (unsigned n = 1; n <= 4; ++n) {
        oss << "ost 00000000-0000-7000-8000-00000000000" << n
            << " 127.0.0.1:875" << n << " 100 dc1/rack" << (1 + n % 2)
            << "/host" << n << "\n";
    }
    std::istringstream in(oss.str());
    return Topology::parse(in);
}

std::string db_path(const char* name) {
    std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "rawstor_mds_test";
    std::filesystem::create_directories(dir);
    std::filesystem::path db = dir / name;
    std::filesystem::remove(db);
    std::filesystem::remove(db.string() + "-wal");
    std::filesystem::remove(db.string() + "-shm");
    return db.string();
}

RawstdUUID fresh_uuid() {
    RawstdUUID ret;
    EXPECT_EQ(rawstd_uuid7_init(&ret), 0);
    return ret;
}

PlacementPolicy mirror2() {
    PlacementPolicy policy{};
    policy.width = 2;
    policy.failure_domain = Level::Server;
    policy.stripe_width = STRIPE_ALL;
    policy.seed = 7;
    return policy;
}

TEST(MdsStoreTest, create_open_map_shape) {
    VolumeStore store(db_path("shape.db"), topology_4_hosts());

    /* 8 MiB volume, 1 MiB chunks: 8 chunks x 2 slots. */
    VolumeDescriptor d =
        store.create(fresh_uuid(), 8ull << 20, 1ull << 20, mirror2());
    EXPECT_EQ(d.map_epoch, 1u);

    VolumeMap map = store.open(d.volume_id, 0);
    EXPECT_EQ(map.descriptor.logical_size, 8ull << 20);
    EXPECT_EQ(map.descriptor.chunk_size, 1ull << 20);
    EXPECT_EQ(map.descriptor.policy.width, 2u);
    EXPECT_EQ(map.descriptor.map_epoch, 1u);
    ASSERT_EQ(map.chunks.size(), 8u);

    for (const std::vector<PlacementSlot>& slots : map.chunks) {
        ASSERT_EQ(slots.size(), 2u);
        EXPECT_EQ(slots[0].slot_index, 0);
        EXPECT_EQ(slots[1].slot_index, 1);
        /* Distinct OSTs per chunk (server-level domains). */
        EXPECT_NE(
            memcmp(
                slots[0].ost_id.bytes, slots[1].ost_id.bytes,
                sizeof(slots[0].ost_id.bytes)
            ),
            0
        );
    }

    /* Snapshots are stage 2. */
    EXPECT_THROW(store.open(d.volume_id, 42), std::system_error);
}

TEST(MdsStoreTest, map_survives_reopen) {
    std::string path = db_path("durability.db");
    RawstdUUID volume_id;
    VolumeMap before;

    {
        VolumeStore store(path, topology_4_hosts());
        VolumeDescriptor d =
            store.create(fresh_uuid(), 4ull << 20, 1ull << 20, mirror2());
        volume_id = d.volume_id;
        before = store.open(volume_id, 0);
    }

    VolumeStore store(path, topology_4_hosts());
    VolumeMap after = store.open(volume_id, 0);

    ASSERT_EQ(after.chunks.size(), before.chunks.size());
    for (size_t i = 0; i < after.chunks.size(); ++i) {
        ASSERT_EQ(after.chunks[i].size(), before.chunks[i].size());
        for (size_t s = 0; s < after.chunks[i].size(); ++s) {
            EXPECT_EQ(
                memcmp(
                    after.chunks[i][s].ost_id.bytes,
                    before.chunks[i][s].ost_id.bytes,
                    sizeof(after.chunks[i][s].ost_id.bytes)
                ),
                0
            );
        }
    }
}

TEST(MdsStoreTest, resize_grows_and_keeps_old_chunks) {
    VolumeStore store(db_path("resize.db"), topology_4_hosts());

    VolumeDescriptor d =
        store.create(fresh_uuid(), 2ull << 20, 1ull << 20, mirror2());
    VolumeMap before = store.open(d.volume_id, 0);
    ASSERT_EQ(before.chunks.size(), 2u);

    uint64_t map_epoch = store.resize(d.volume_id, 4ull << 20);
    EXPECT_EQ(map_epoch, 2u);

    VolumeMap after = store.open(d.volume_id, 0);
    ASSERT_EQ(after.chunks.size(), 4u);

    /* The old placements must not move. */
    for (size_t i = 0; i < before.chunks.size(); ++i) {
        for (size_t s = 0; s < before.chunks[i].size(); ++s) {
            EXPECT_EQ(
                memcmp(
                    after.chunks[i][s].ost_id.bytes,
                    before.chunks[i][s].ost_id.bytes,
                    sizeof(after.chunks[i][s].ost_id.bytes)
                ),
                0
            );
        }
    }

    /* Shrink is not supported in v1. */
    EXPECT_THROW(store.resize(d.volume_id, 1ull << 20), std::system_error);
}

TEST(MdsStoreTest, remove) {
    VolumeStore store(db_path("remove.db"), topology_4_hosts());

    VolumeDescriptor d =
        store.create(fresh_uuid(), 2ull << 20, 1ull << 20, mirror2());
    store.remove(d.volume_id);

    EXPECT_THROW(store.open(d.volume_id, 0), std::system_error);
    EXPECT_THROW(store.remove(d.volume_id), std::system_error);
}

TEST(MdsStoreTest, invalid_geometry_and_unsatisfiable_policy) {
    VolumeStore store(db_path("invalid.db"), topology_4_hosts());

    /* Chunk size must be a power of two. */
    EXPECT_THROW(
        store.create(fresh_uuid(), 8ull << 20, 3ull << 19, mirror2()),
        std::system_error
    );
    EXPECT_THROW(
        store.create(fresh_uuid(), 0, 1ull << 20, mirror2()), std::system_error
    );

    /* 3 copies over 1 dc is unsatisfiable at the dc level: hard fail. */
    PlacementPolicy policy = mirror2();
    policy.width = 3;
    policy.failure_domain = Level::DC;
    EXPECT_THROW(
        store.create(fresh_uuid(), 8ull << 20, 1ull << 20, policy),
        std::system_error
    );
}

TEST(MdsStoreTest, snapshot_lifecycle) {
    std::string path = db_path("snapshot.db");
    Topology topology = topology_4_hosts();

    RawstdUUID volume_id;
    uint64_t snap_id;

    {
        VolumeStore store(path, topology);

        /* 2 MiB volume, 1 MiB chunks: 2 chunks x 2 slots. */
        VolumeDescriptor d =
            store.create(fresh_uuid(), 2ull << 20, 1ull << 20, mirror2());
        volume_id = d.volume_id;

        snap_id = store.snap_begin(volume_id);
        EXPECT_EQ(snap_id, 1u);

        /* Uncommitted: the reservation alone registers nothing. */
        EXPECT_THROW(store.open(volume_id, snap_id), std::system_error);

        VolumeMap live = store.open(volume_id, 0);
        std::vector<rawstor::mds::SnapMember> members;
        for (size_t index = 0; index < live.chunks.size(); ++index) {
            for (const PlacementSlot& slot : live.chunks[index]) {
                members.push_back({index, slot.ost_id});
            }
        }

        uint64_t map_epoch = store.snap_commit(volume_id, snap_id, members);
        EXPECT_EQ(map_epoch, 2u);

        /* Registering the same id twice would alias two points in time. */
        EXPECT_THROW(
            store.snap_commit(volume_id, snap_id, members), std::system_error
        );
        /* An id that was never reserved is refused. */
        EXPECT_THROW(
            store.snap_commit(volume_id, 42, members), std::system_error
        );
    }

    /* The registry and the reservation counter survive a reopen. */
    VolumeStore store(path, topology);

    VolumeMap view = store.open(volume_id, snap_id);
    EXPECT_EQ(view.descriptor.logical_size, 2ull << 20);
    ASSERT_EQ(view.chunks.size(), 2u);
    for (const std::vector<PlacementSlot>& slots : view.chunks) {
        EXPECT_EQ(slots.size(), 2u);
    }

    /* Reserved ids never repeat, even after the snapshot is gone. */
    EXPECT_EQ(store.snap_begin(volume_id), 2u);

    /* The volume must not disappear under its snapshots. */
    EXPECT_THROW(store.remove(volume_id), std::system_error);

    std::vector<rawstor::mds::SnapMember> removed =
        store.snap_remove(volume_id, snap_id);
    EXPECT_EQ(removed.size(), 4u);
    EXPECT_THROW(store.open(volume_id, snap_id), std::system_error);
    EXPECT_THROW(store.snap_remove(volume_id, snap_id), std::system_error);

    store.remove(volume_id);
}

TEST(MdsStoreTest, snapshot_must_cover_every_chunk) {
    VolumeStore store(db_path("snapshot_cover.db"), topology_4_hosts());

    VolumeDescriptor d =
        store.create(fresh_uuid(), 2ull << 20, 1ull << 20, mirror2());

    uint64_t snap_id = store.snap_begin(d.volume_id);

    VolumeMap live = store.open(d.volume_id, 0);

    /* Chunk 1 has no member: an unreadable snapshot is never registered. */
    std::vector<rawstor::mds::SnapMember> holed = {
        {0, live.chunks[0][0].ost_id},
        {0, live.chunks[0][1].ost_id},
    };
    EXPECT_THROW(
        store.snap_commit(d.volume_id, snap_id, holed), std::system_error
    );

    /* A degraded snapshot (one member of two on a chunk) registers. */
    std::vector<rawstor::mds::SnapMember> degraded = {
        {0, live.chunks[0][0].ost_id},
        {0, live.chunks[0][1].ost_id},
        {1, live.chunks[1][0].ost_id},
    };
    EXPECT_EQ(store.snap_commit(d.volume_id, snap_id, degraded), 2u);

    VolumeMap view = store.open(d.volume_id, snap_id);
    ASSERT_EQ(view.chunks.size(), 2u);
    EXPECT_EQ(view.chunks[0].size(), 2u);
    EXPECT_EQ(view.chunks[1].size(), 1u);
}

TEST(MdsStoreTest, snapshot_freezes_size_across_resize) {
    VolumeStore store(db_path("snapshot_resize.db"), topology_4_hosts());

    VolumeDescriptor d =
        store.create(fresh_uuid(), 2ull << 20, 1ull << 20, mirror2());

    uint64_t snap_id = store.snap_begin(d.volume_id);
    VolumeMap live = store.open(d.volume_id, 0);
    std::vector<rawstor::mds::SnapMember> members;
    for (size_t index = 0; index < live.chunks.size(); ++index) {
        for (const PlacementSlot& slot : live.chunks[index]) {
            members.push_back({index, slot.ost_id});
        }
    }
    store.snap_commit(d.volume_id, snap_id, members);

    store.resize(d.volume_id, 4ull << 20);

    /* The live view grew; the snapshot view kept its size. */
    EXPECT_EQ(store.open(d.volume_id, 0).chunks.size(), 4u);
    VolumeMap view = store.open(d.volume_id, snap_id);
    EXPECT_EQ(view.descriptor.logical_size, 2ull << 20);
    EXPECT_EQ(view.chunks.size(), 2u);
}

rawstor::mds::ScanRecord scan_record(
    const RawstdUUID& ost_id, const RawstdUUID& volume_id, uint64_t index,
    uint64_t chunk_size, uint64_t size, unsigned width
) {
    rawstor::mds::ScanRecord r{};
    r.ost_id = ost_id;
    EXPECT_EQ(rawstd_uuid7_init(&r.obj_id), 0);
    r.meta.size = size;
    r.meta.state = RAWSTOR_OBJECT_STATE_CLEAN;
    r.meta.member_kind = RAWSTOR_MEMBER_DATA;
    r.meta.width = static_cast<uint8_t>(width);
    memcpy(r.meta.volume_id, volume_id.bytes, sizeof(r.meta.volume_id));
    r.meta.logical_index = index;
    r.meta.chunk_size = chunk_size;
    r.meta.snap_version = 0;
    return r;
}

TEST(MdsStoreTest, reconstruct_rebuilds_map) {
    Topology topology = topology_4_hosts();
    const RawstdUUID& ost1 = topology.osts()[0].id;
    const RawstdUUID& ost2 = topology.osts()[1].id;

    RawstdUUID volume_id = fresh_uuid();

    /* 2 chunks x 2 copies; the tail chunk is half-filled. */
    std::vector<rawstor::mds::ScanRecord> records = {
        scan_record(ost1, volume_id, 0, 1ull << 20, 1ull << 20, 2),
        scan_record(ost2, volume_id, 0, 1ull << 20, 1ull << 20, 2),
        scan_record(ost1, volume_id, 1, 1ull << 20, 1ull << 19, 2),
        scan_record(ost2, volume_id, 1, 1ull << 20, 1ull << 19, 2),
    };

    /* Records the reconstruct must ignore. */
    {
        /* A standalone object: all-zero volume_id. */
        RawstdUUID null_volume{};
        records.push_back(
            scan_record(ost1, null_volume, 0, 1ull << 20, 1ull << 20, 1)
        );
        /* A witness slot (stage 3). */
        rawstor::mds::ScanRecord witness =
            scan_record(ost1, volume_id, 0, 1ull << 20, 1ull << 20, 2);
        witness.meta.member_kind = RAWSTOR_MEMBER_WITNESS;
        records.push_back(witness);
        /* A snapshot version (stage 2). */
        rawstor::mds::ScanRecord snap =
            scan_record(ost1, volume_id, 0, 1ull << 20, 1ull << 20, 2);
        snap.meta.snap_version = 5;
        records.push_back(snap);
    }

    VolumeStore store(db_path("reconstruct.db"), topology);

    /* A pre-existing volume must be replaced by the rebuilt map. */
    VolumeDescriptor stale =
        store.create(fresh_uuid(), 1ull << 20, 1ull << 20, mirror2());

    store.reconstruct(records);

    VolumeMap map = store.open(volume_id, 0);
    EXPECT_EQ(map.descriptor.logical_size, (1ull << 20) + (1ull << 19));
    EXPECT_EQ(map.descriptor.chunk_size, 1ull << 20);
    EXPECT_EQ(map.descriptor.policy.width, 2u);
    EXPECT_EQ(map.descriptor.map_epoch, 1u);
    ASSERT_EQ(map.chunks.size(), 2u);
    for (const std::vector<PlacementSlot>& slots : map.chunks) {
        ASSERT_EQ(slots.size(), 2u);
        EXPECT_EQ(
            memcmp(slots[0].ost_id.bytes, ost1.bytes, sizeof(ost1.bytes)), 0
        );
        EXPECT_EQ(
            memcmp(slots[1].ost_id.bytes, ost2.bytes, sizeof(ost2.bytes)), 0
        );
    }

    /* The pre-existing volume is gone: the scan is the whole truth. */
    EXPECT_THROW(store.open(stale.volume_id, 0), std::system_error);
}

TEST(MdsStoreTest, reconstruct_degraded_and_broken_volumes) {
    Topology topology = topology_4_hosts();
    const RawstdUUID& ost1 = topology.osts()[0].id;
    const RawstdUUID& ost2 = topology.osts()[1].id;

    VolumeStore store(db_path("reconstruct_bad.db"), topology);

    /* One surviving copy of one chunk: degraded but reassemblable. */
    RawstdUUID degraded = fresh_uuid();
    store.reconstruct({
        scan_record(ost1, degraded, 0, 1ull << 20, 1ull << 20, 2),
        scan_record(ost2, degraded, 0, 1ull << 20, 1ull << 20, 2),
        scan_record(ost1, degraded, 1, 1ull << 20, 1ull << 20, 2),
    });
    VolumeMap map = store.open(degraded, 0);
    ASSERT_EQ(map.chunks.size(), 2u);
    EXPECT_EQ(map.chunks[0].size(), 2u);
    EXPECT_EQ(map.chunks[1].size(), 1u);

    /* A hole in the chunk index sequence: no copy of chunk 1 at all. */
    RawstdUUID holed = fresh_uuid();
    EXPECT_THROW(
        store.reconstruct({
            scan_record(ost1, holed, 0, 1ull << 20, 1ull << 20, 2),
            scan_record(ost1, holed, 2, 1ull << 20, 1ull << 20, 2),
        }),
        std::system_error
    );

    /* Conflicting identity records within one volume. */
    RawstdUUID conflicted = fresh_uuid();
    EXPECT_THROW(
        store.reconstruct({
            scan_record(ost1, conflicted, 0, 1ull << 20, 1ull << 20, 2),
            scan_record(ost2, conflicted, 0, 1ull << 19, 1ull << 19, 2),
        }),
        std::system_error
    );

    /* A failed reconstruct must not have destroyed the previous map. */
    map = store.open(degraded, 0);
    ASSERT_EQ(map.chunks.size(), 2u);
}

} // unnamed namespace
