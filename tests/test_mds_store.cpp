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
    VolumeDescriptor d = store.create(8ull << 20, 1ull << 20, mirror2());
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
        VolumeDescriptor d = store.create(4ull << 20, 1ull << 20, mirror2());
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

    VolumeDescriptor d = store.create(2ull << 20, 1ull << 20, mirror2());
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

    VolumeDescriptor d = store.create(2ull << 20, 1ull << 20, mirror2());
    store.remove(d.volume_id);

    EXPECT_THROW(store.open(d.volume_id, 0), std::system_error);
    EXPECT_THROW(store.remove(d.volume_id), std::system_error);
}

TEST(MdsStoreTest, invalid_geometry_and_unsatisfiable_policy) {
    VolumeStore store(db_path("invalid.db"), topology_4_hosts());

    /* Chunk size must be a power of two. */
    EXPECT_THROW(
        store.create(8ull << 20, 3ull << 19, mirror2()), std::system_error
    );
    EXPECT_THROW(store.create(0, 1ull << 20, mirror2()), std::system_error);

    /* 3 copies over 1 dc is unsatisfiable at the dc level: hard fail. */
    PlacementPolicy policy = mirror2();
    policy.width = 3;
    policy.failure_domain = Level::DC;
    EXPECT_THROW(
        store.create(8ull << 20, 1ull << 20, policy), std::system_error
    );
}

} // unnamed namespace
