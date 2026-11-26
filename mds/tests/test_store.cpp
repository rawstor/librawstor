#include "tmp_dir.hpp"
#include <rawstor/pki.h>

#include <mds/placement.hpp>
#include <mds/store.hpp>
#include <mds/topology.hpp>

#include "ost_registration.hpp"

#include <rawstor/target.h>

#include <rawtls/spiffe.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uuid.h>

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <functional>

namespace {

using rawstor::mdsserver::Level;
using rawstor::mdsserver::ObjectDescriptor;
using rawstor::mdsserver::ObjectMap;
using rawstor::mdsserver::ObjectStore;
using rawstor::mdsserver::PlacementPolicy;
using rawstor::mdsserver::ResizeResult;
using rawstor::mdsserver::ScanRecord;
using rawstor::mdsserver::STRIPE_ALL;
using rawstor::mdsserver::Topology;
using rawstor::mdsserver::TopologyOST;
using rawstor::mdsserver::VersionMember;

constexpr uint64_t chunk_size = 1ull << 16;

TopologyOST make_ost(const char* id, const char* host) {
    TopologyOST ost{};
    if (rawstd_uuid_from_string(&ost.id, id) < 0) {
        RAWSTD_THROW_ERRNO();
    }
    ost.location = std::string("ost://") + host + ":7777";
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

// Every account of the registry, read a page at a time.
std::vector<RawstdUUID>
all_accounts(ObjectStore& store, unsigned int limit = 2) {
    std::vector<RawstdUUID> ret;
    RawstdUUID token{};
    do {
        std::vector<RawstdUUID> page = store.list_accounts(token, limit);
        EXPECT_LE(page.size(), limit);
        ret.insert(ret.end(), page.begin(), page.end());
    } while (!rawstd_uuid_is_nil(&token));
    return ret;
}

// What `ost` sends when it registers, with `info` as its sample if given.
rawstor::OstRegistration registration_of(
    const TopologyOST& ost, const RawstorLocationInfo* info = nullptr,
    bool leaving = false
) {
    rawstor::OstRegistration ret;
    ret.id = ost.id;
    ret.location = ost.location;
    ret.weight = ost.weight;
    for (const std::string& part : ost.path) {
        if (!part.empty()) {
            ret.domain += (ret.domain.empty() ? "" : "/") + part;
        }
    }
    if (info != nullptr) {
        ret.sampled = true;
        ret.info = *info;
    }
    ret.leaving = leaving;
    return ret;
}

void register_all(
    ObjectStore& store, const Topology& topology,
    const RawstorLocationInfo* info = nullptr
) {
    for (const TopologyOST& ost : topology.osts()) {
        store.register_ost(registration_of(ost, info));
    }
}

void leave(ObjectStore& store, const TopologyOST& ost) {
    store.register_ost(registration_of(ost, nullptr, true));
}

int errno_of(const std::function<void()>& call) {
    try {
        call();
    } catch (const std::system_error& e) {
        return e.code().value();
    }
    return 0;
}

class ObjectStoreTest : public testing::Test {
protected:
    rawstor::mdsserver::tests::TmpDir dir;
    std::unique_ptr<ObjectStore> _store;

    // A store with make_topology()'s three OSTs registered.
    ObjectStore& make_store() {
        _store = std::make_unique<ObjectStore>(dir.db_path());
        register_all(*_store, make_topology());
        return *_store;
    }
};

TEST_F(ObjectStoreTest, create_populates_chunk_map) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();

    ObjectDescriptor descriptor = store.create(
        RawstdUUID{}, RawstdUUID{}, id, 3 * chunk_size, chunk_size,
        make_policy(1)
    );

    EXPECT_EQ(descriptor.logical_size, 3 * chunk_size);
    EXPECT_EQ(descriptor.chunk_size, chunk_size);
    EXPECT_EQ(descriptor.map_version, 1u);

    ObjectMap map = store.open(id, RawstdUUID{});
    ASSERT_EQ(map.chunks.size(), 3u);
    for (const auto& slots : map.chunks) {
        EXPECT_EQ(slots.size(), 1u);
    }
}

TEST_F(ObjectStoreTest, create_rejects_duplicate_id) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();

    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    EXPECT_THROW(
        store.create(
            RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size,
            make_policy(1)
        ),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_zero_size) {
    ObjectStore& store = make_store();

    EXPECT_THROW(
        store.create(
            RawstdUUID{}, RawstdUUID{}, make_id(), 0, chunk_size, make_policy(1)
        ),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_non_power_of_two_chunk_size) {
    ObjectStore& store = make_store();

    EXPECT_THROW(
        store.create(
            RawstdUUID{}, RawstdUUID{}, make_id(), chunk_size, 3, make_policy(1)
        ),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_size_not_chunk_multiple) {
    ObjectStore& store = make_store();

    EXPECT_THROW(
        store.create(
            RawstdUUID{}, RawstdUUID{}, make_id(), chunk_size + 4096,
            chunk_size, make_policy(1)
        ),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_rejects_unsatisfiable_placement) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();

    // Only 3 OST-level domains exist; width 4 can never be satisfied.
    EXPECT_THROW(
        store.create(
            RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size,
            make_policy(4)
        ),
        std::system_error
    );

    // Nothing landed -- the unsatisfiable check runs before any write
    // (own doc comment, store.cpp: "Hard-fails on an unsatisfiable
    // topology before anything lands").
    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, registering_adds_an_ost) {
    ObjectStore& store = make_store();
    store.create(
        RawstdUUID{}, RawstdUUID{}, make_id(), chunk_size, chunk_size,
        make_policy(3)
    );

    TopologyOST fourth =
        make_ost("00000000-0000-7000-8000-000000000004", "host4");
    store.register_ost(registration_of(fourth));

    auto topology = store.topology();
    EXPECT_EQ(topology->osts().size(), 4u);
    EXPECT_TRUE(store.backend_available(fourth.id));
    // Every OST is a DATA and witness candidate.
    for (const TopologyOST& ost : topology->osts()) {
        EXPECT_TRUE(ost.supports(rawstor::mdsserver::Role::Data));
        EXPECT_TRUE(ost.supports(rawstor::mdsserver::Role::Witness));
    }
}

// Three heartbeats: an OST that has not registered since is unavailable, and
// registering again makes it available.
TEST_F(ObjectStoreTest, a_registration_lasts_three_heartbeats) {
    rawstor::mdsserver::Opts opts;
    opts.heartbeat_interval = 1;
    ObjectStore store(dir.db_path(), opts);
    TopologyOST ost = make_ost("00000000-0000-7000-8000-000000000001", "host1");
    store.register_ost(registration_of(ost));
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(store.backend_available(ost.id));
    EXPECT_EQ(
        errno_of([&] {
            store.create(
                RawstdUUID{}, {}, make_id(), chunk_size, chunk_size,
                make_policy(1)
            );
        }),
        EINVAL
    );
    store.register_ost(registration_of(ost));
    EXPECT_TRUE(store.backend_available(ost.id));
}

TEST_F(ObjectStoreTest, an_unavailable_ost_holding_chunks_stays) {
    ObjectStore& store = make_store();
    // Width 3 of 3 OSTs: every OST holds a copy.
    store.create(
        RawstdUUID{}, RawstdUUID{}, make_id(), chunk_size, chunk_size,
        make_policy(3)
    );

    Topology topology = make_topology();
    for (const TopologyOST& ost : topology.osts()) {
        leave(store, ost);
        EXPECT_FALSE(store.backend_available(ost.id));
    }
    EXPECT_EQ(store.topology()->osts().size(), 3u);
}

TEST_F(ObjectStoreTest, an_unavailable_ost_holding_nothing_leaves) {
    ObjectStore& store = make_store();
    TopologyOST first = make_topology().osts()[0];

    leave(store, first);

    auto topology = store.topology();
    ASSERT_EQ(topology->osts().size(), 2u);
    for (const TopologyOST& ost : topology->osts()) {
        EXPECT_NE(rawstd_uuid_cmp(&ost.id, &first.id), 0);
    }
    // It comes back by registering again.
    store.register_ost(registration_of(first));
    EXPECT_EQ(store.topology()->osts().size(), 3u);
}

// One id is one OST: while it is available, another process registering the
// same id elsewhere is refused; once it is gone, the id may move.
TEST_F(ObjectStoreTest, an_ost_moves_only_while_unavailable) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, {}, id, chunk_size, chunk_size, make_policy(3));
    TopologyOST moved = make_topology().osts()[0];
    moved.location = "ost://127.0.0.1:7778";

    EXPECT_EQ(
        errno_of([&] { store.register_ost(registration_of(moved)); }), EEXIST
    );
    leave(store, make_topology().osts()[0]);
    store.register_ost(registration_of(moved));

    EXPECT_TRUE(store.backend_available(moved.id));
    bool found = false;
    auto topology = store.topology();
    for (const TopologyOST& ost : topology->osts()) {
        if (rawstd_uuid_cmp(&ost.id, &moved.id) == 0) {
            EXPECT_EQ(ost.location, moved.location);
            found = true;
        }
    }
    EXPECT_TRUE(found);
}

// A domain or weight is the OST's to set: a new one is taken, and the chunks
// already placed stay where they are.
TEST_F(ObjectStoreTest, a_new_domain_or_weight_is_taken) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, {}, id, chunk_size, chunk_size, make_policy(3));
    ObjectMap before = store.open(id, {});

    TopologyOST changed = make_topology().osts()[0];
    changed.path[2] = "rack2";
    changed.weight = 7;
    store.register_ost(registration_of(changed));

    const TopologyOST entry = store.topology()->osts()[0];
    EXPECT_EQ(entry.path[2], "rack2");
    EXPECT_EQ(entry.weight, 7u);
    ObjectMap after = store.open(id, {});
    ASSERT_EQ(after.chunks[0].size(), before.chunks[0].size());
    for (size_t i = 0; i < after.chunks[0].size(); ++i) {
        EXPECT_EQ(
            rawstd_uuid_cmp(
                &after.chunks[0][i].ost_id, &before.chunks[0][i].ost_id
            ),
            0
        );
    }
}

TEST_F(ObjectStoreTest, a_malformed_registration_is_refused) {
    ObjectStore store(dir.db_path());
    TopologyOST ost = make_ost("00000000-0000-7000-8000-000000000001", "host1");
    for (const char* location :
         {"mds://host1:7776", "ost://host1:7777,ost://host2:7777", ""}) {
        rawstor::OstRegistration registration = registration_of(ost);
        registration.location = location;
        EXPECT_EQ(errno_of([&] { store.register_ost(registration); }), EINVAL)
            << location;
    }
    for (const char* domain : {"", "a//b", "a/b/c/d/e"}) {
        rawstor::OstRegistration registration = registration_of(ost);
        registration.domain = domain;
        EXPECT_EQ(errno_of([&] { store.register_ost(registration); }), EINVAL)
            << domain;
    }
    rawstor::OstRegistration nil = registration_of(ost);
    nil.id = RawstdUUID{};
    EXPECT_EQ(errno_of([&] { store.register_ost(nil); }), EINVAL);
    EXPECT_TRUE(store.topology()->osts().empty());
}

TEST_F(ObjectStoreTest, only_an_ost_registers_and_only_as_itself) {
    RawstdUUID id{};
    ASSERT_EQ(
        rawstd_uuid_from_string(&id, "00000000-0000-7000-8000-000000000001"), 0
    );
    rawtls::SpiffeId self(
        "spiffe://cluster.example/ost/00000000-0000-7000-8000-000000000001"
    );
    rawtls::SpiffeId other(
        "spiffe://cluster.example/ost/00000000-0000-7000-8000-000000000002"
    );
    rawtls::SpiffeId mds(
        "spiffe://cluster.example/mds/00000000-0000-7000-8000-000000000001"
    );
    rawtls::SpiffeId admin("spiffe://cluster.example/admin/ops");

    EXPECT_EQ(
        errno_of([&] { ObjectStore::authorize_registration(nullptr, id); }), 0
    );
    EXPECT_EQ(
        errno_of([&] { ObjectStore::authorize_registration(&self, id); }), 0
    );
    EXPECT_EQ(
        errno_of([&] { ObjectStore::authorize_registration(&other, id); }),
        EPERM
    );
    EXPECT_EQ(
        errno_of([&] { ObjectStore::authorize_registration(&mds, id); }), EACCES
    );
    EXPECT_EQ(
        errno_of([&] { ObjectStore::authorize_registration(&admin, id); }),
        EACCES
    );
}

// While the map is rebuilt, only the OSTs it is rebuilt from get through:
// they connect and register, everything else is answered later.
TEST_F(ObjectStoreTest, a_reconstruct_holds_back_everything_but_registration) {
    ObjectStore& store = make_store();
    rawtls::SpiffeId admin("spiffe://cluster.example/admin/ops");
    store.set_reconstructing(true);

    EXPECT_EQ(
        errno_of([&] { store.authorize(&admin, RAWSTOR_CMD_LIST); }), EAGAIN
    );
    EXPECT_EQ(
        errno_of([&] { store.authorize(nullptr, RAWSTOR_CMD_OBJ_CREATE); }),
        EAGAIN
    );
    EXPECT_EQ(
        errno_of([&] { store.authorize(&admin, RAWSTOR_CMD_SET_OBJECT); }), 0
    );
    TopologyOST fourth =
        make_ost("00000000-0000-7000-8000-000000000004", "host4");
    store.register_ost(registration_of(fourth));
    EXPECT_EQ(store.available_osts().size(), 4u);

    store.set_reconstructing(false);
    EXPECT_EQ(errno_of([&] { store.authorize(&admin, RAWSTOR_CMD_LIST); }), 0);
}

// The OSTs a reconstruct scans: the available ones, not the MDS's own
// witness.
TEST_F(ObjectStoreTest, the_available_osts_leave_out_the_local_witness) {
    ObjectStore& store = make_store();
    TopologyOST mds = make_ost("00000000-0000-7000-8000-000000000004", "host4");
    mds.roles = {rawstor::mdsserver::Role::Witness};
    store.set_local_witness(mds);
    leave(store, make_topology().osts()[2]);

    std::vector<TopologyOST> available = store.available_osts();
    ASSERT_EQ(available.size(), 2u);
    for (const TopologyOST& ost : available) {
        EXPECT_FALSE(ost.witness_only());
    }
}

// A store of layout 1 kept the space samples of a topology read from a file:
// its entries keep their addresses and samples, and take chunks once their
// OSTs register.
TEST_F(ObjectStoreTest, a_store_of_layout_1_keeps_its_entries) {
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open(dir.db_path().c_str(), &db), SQLITE_OK);
        const char* sql =
            "CREATE TABLE backends ("
            " id BLOB PRIMARY KEY, location TEXT NOT NULL,"
            " active INTEGER NOT NULL, available INTEGER NOT NULL DEFAULT 0,"
            " used INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT "
            "0,"
            " checked_at INTEGER NOT NULL DEFAULT 0,"
            " sampled_at INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;"
            "INSERT INTO backends (id, location, active, available, used, "
            "total) VALUES (x'00000000000070008000000000000001', "
            "'ost://host1:7777', 1, 1, 10, 100);"
            "PRAGMA user_version=1;";
        ASSERT_EQ(sqlite3_exec(db, sql, nullptr, nullptr, nullptr), SQLITE_OK);
        sqlite3_close(db);
    }
    ObjectStore store(dir.db_path());
    TopologyOST ost = make_ost("00000000-0000-7000-8000-000000000001", "host1");

    ASSERT_EQ(store.topology()->osts().size(), 1u);
    EXPECT_EQ(store.topology()->osts()[0].location, "ost://host1:7777");
    EXPECT_EQ(store.info().total, 100u);
    EXPECT_FALSE(store.backend_available(ost.id));

    store.register_ost(registration_of(ost));
    EXPECT_TRUE(store.backend_available(ost.id));
    EXPECT_EQ(store.topology()->osts()[0].path[3], "host1");
    store.create(
        RawstdUUID{}, {}, make_id(), chunk_size, chunk_size, make_policy(1)
    );
}

// Idempotent mutations (docs/mds.md): a repeated idempotency_key replays the
// first call's result instead of applying anything again.
TEST_F(ObjectStoreTest, create_replays_repeated_idempotency_key) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();

    ObjectDescriptor first = store.create(
        RawstdUUID{}, idempotency_key, id, chunk_size, chunk_size,
        make_policy(1)
    );
    ObjectDescriptor again = store.create(
        RawstdUUID{}, idempotency_key, id, chunk_size, chunk_size,
        make_policy(1)
    );
    EXPECT_EQ(again.map_version, first.map_version);

    // A different op for the same id is a genuine second create.
    EXPECT_THROW(
        store.create(
            RawstdUUID{}, make_id(), id, chunk_size, chunk_size, make_policy(1)
        ),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, create_replayed_after_rollback_creates_afresh) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();

    store.create(
        RawstdUUID{}, idempotency_key, id, chunk_size, chunk_size,
        make_policy(1)
    );
    store.remove(make_id(), id);

    store.create(
        RawstdUUID{}, idempotency_key, id, chunk_size, chunk_size,
        make_policy(1)
    );
    EXPECT_NO_THROW(store.open(id, RawstdUUID{}));
}

TEST_F(ObjectStoreTest, resize_replays_repeated_idempotency_key) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    ResizeResult first = store.resize(idempotency_key, id, 3 * chunk_size);
    ResizeResult again = store.resize(idempotency_key, id, 3 * chunk_size);

    EXPECT_EQ(first.old_nchunks, 1u);
    EXPECT_EQ(again.old_nchunks, 1u);
    EXPECT_EQ(again.map_version, first.map_version);
    EXPECT_EQ(
        store.open(id, RawstdUUID{}).descriptor.map_version, first.map_version
    );
}

TEST_F(ObjectStoreTest, remove_replays_the_removed_map) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, 2 * chunk_size, chunk_size,
        make_policy(1)
    );

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

TEST_F(ObjectStoreTest, versions_replay_repeated_idempotency_key) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID version_id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    ObjectMap map = store.open(id, RawstdUUID{});
    std::vector<VersionMember> members{{0, map.chunks[0][0].ost_id}};

    RawstdUUID commit_op = make_id();
    uint64_t first = store.commit_version(commit_op, id, version_id, members);
    EXPECT_EQ(store.commit_version(commit_op, id, version_id, members), first);

    RawstdUUID remove_op = make_id();
    std::vector<VersionMember> removed =
        store.remove_version(remove_op, id, version_id);
    std::vector<VersionMember> again =
        store.remove_version(remove_op, id, version_id);
    ASSERT_EQ(removed.size(), 1u);
    ASSERT_EQ(again.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&again[0].ost_id, &removed[0].ost_id), 0);
}

TEST_F(ObjectStoreTest, idempotency_key_reused_for_another_call_is_einval) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    RawstdUUID idempotency_key = make_id();
    store.create(
        RawstdUUID{}, idempotency_key, id, chunk_size, chunk_size,
        make_policy(1)
    );

    try {
        store.resize(idempotency_key, id, 2 * chunk_size);
        FAIL() << "expected EINVAL";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EINVAL);
    }
}

TEST_F(ObjectStoreTest, open_rejects_unknown_id) {
    ObjectStore& store = make_store();

    EXPECT_THROW(store.open(make_id(), RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, resize_grows_chunk_count_and_bumps_epoch) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    uint64_t map_version =
        store.resize(RawstdUUID{}, id, 3 * chunk_size).map_version;

    EXPECT_EQ(map_version, 2u);
    ObjectMap map = store.open(id, RawstdUUID{});
    EXPECT_EQ(map.descriptor.logical_size, 3 * chunk_size);
    EXPECT_EQ(map.descriptor.map_version, 2u);
    ASSERT_EQ(map.chunks.size(), 3u);
    for (const auto& slots : map.chunks) {
        EXPECT_EQ(slots.size(), 1u);
    }
}

TEST_F(ObjectStoreTest, resize_rejects_shrink) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, 3 * chunk_size, chunk_size,
        make_policy(1)
    );

    EXPECT_THROW(store.resize(RawstdUUID{}, id, chunk_size), std::system_error);
}

TEST_F(ObjectStoreTest, resize_rejects_size_not_chunk_multiple) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    EXPECT_THROW(
        store.resize(RawstdUUID{}, id, 2 * chunk_size + 4096), std::system_error
    );

    ObjectMap map = store.open(id, RawstdUUID{});
    EXPECT_EQ(map.descriptor.logical_size, chunk_size);
    EXPECT_EQ(map.descriptor.map_version, 1u);
}

TEST_F(ObjectStoreTest, resize_rejects_zero_size) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    EXPECT_THROW(store.resize(RawstdUUID{}, id, 0), std::system_error);
}

TEST_F(ObjectStoreTest, remove_deletes_object) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    store.remove(RawstdUUID{}, id);

    EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
}

TEST_F(ObjectStoreTest, remove_rejects_unknown_id) {
    ObjectStore& store = make_store();

    EXPECT_THROW(store.remove(RawstdUUID{}, make_id()), std::system_error);
}

TEST_F(ObjectStoreTest, remove_rejects_while_version_exists) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    RawstdUUID version_id = make_id();
    ObjectMap map = store.open(id, RawstdUUID{});
    std::vector<VersionMember> members;
    for (size_t index = 0; index < map.chunks.size(); ++index) {
        for (const auto& slot : map.chunks[index]) {
            members.push_back(VersionMember{index, slot.ost_id});
        }
    }
    store.commit_version(RawstdUUID{}, id, version_id, members);

    EXPECT_THROW(store.remove(RawstdUUID{}, id), std::system_error);

    // Removing the version first clears the way.
    store.remove_version(RawstdUUID{}, id, version_id);
    store.remove(RawstdUUID{}, id);
}

TEST_F(ObjectStoreTest, commit_version_and_open_round_trip) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, 2 * chunk_size, chunk_size,
        make_policy(1)
    );
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID version_id = make_id();

    std::vector<VersionMember> members;
    for (size_t index = 0; index < live.chunks.size(); ++index) {
        for (const auto& slot : live.chunks[index]) {
            members.push_back(VersionMember{index, slot.ost_id});
        }
    }
    uint64_t map_version =
        store.commit_version(RawstdUUID{}, id, version_id, members);
    EXPECT_EQ(map_version, 2u);

    ObjectMap version_map = store.open(id, version_id);
    EXPECT_EQ(version_map.descriptor.logical_size, 2 * chunk_size);
    ASSERT_EQ(version_map.chunks.size(), 2u);
    for (size_t index = 0; index < version_map.chunks.size(); ++index) {
        ASSERT_EQ(version_map.chunks[index].size(), 1u);
        EXPECT_EQ(
            rawstd_uuid_cmp(
                &version_map.chunks[index][0].ost_id,
                &live.chunks[index][0].ost_id
            ),
            0
        );
    }
}

TEST_F(ObjectStoreTest, list_objects_pages_by_id) {
    ObjectStore& store = make_store();
    std::vector<RawstdUUID> ids = {make_id(), make_id(), make_id()};
    for (const RawstdUUID& id : ids) {
        store.create(
            RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size,
            make_policy(1)
        );
    }

    RawstdUUID token{};
    auto page = store.list_chunks(RawstdUUID{}, token, 2);
    ASSERT_EQ(page.size(), 2u);
    EXPECT_FALSE(rawstd_uuid_is_nil(&token));
    EXPECT_EQ(rawstd_uuid_cmp(&page[0].id, &ids[0]), 0);
    EXPECT_EQ(rawstd_uuid_cmp(&page[1].id, &ids[1]), 0);
    EXPECT_EQ(page[0].type, RAWSTOR_LIST_ENTRY_OBJECT);

    page = store.list_chunks(RawstdUUID{}, token, 2);
    ASSERT_EQ(page.size(), 1u);
    EXPECT_TRUE(rawstd_uuid_is_nil(&token));
    EXPECT_EQ(rawstd_uuid_cmp(&page[0].id, &ids[2]), 0);
}

// The location URI of the topology entry `id`.
std::string location_of(ObjectStore& store, const RawstdUUID& id) {
    for (const auto& ost : store.topology()->osts()) {
        if (rawstd_uuid_cmp(&ost.id, &id) == 0) {
            return ost.location;
        }
    }
    ADD_FAILURE() << "no such entry";
    return {};
}

// The ids of the objects `store` lists on `location`, a page of `limit` at a
// time.
std::vector<RawstdUUID>
list_on(ObjectStore& store, const std::string& location, unsigned int limit) {
    std::vector<RawstdUUID> ret;
    RawstdUUID token{};
    do {
        auto page = store.list_chunks(RawstdUUID{}, token, limit, location);
        for (const auto& entry : page) {
            EXPECT_EQ(entry.type, RAWSTOR_LIST_ENTRY_OBJECT);
            EXPECT_EQ(entry.offset, 0u);
            ret.push_back(entry.id);
        }
    } while (!rawstd_uuid_is_nil(&token));
    return ret;
}

TEST_F(ObjectStoreTest, list_objects_on_a_location) {
    ObjectStore& store = make_store();
    std::vector<RawstdUUID> ids;
    for (int i = 0; i < 8; ++i) {
        ids.push_back(make_id());
        store.create(
            RawstdUUID{}, RawstdUUID{}, ids.back(), chunk_size, chunk_size,
            make_policy(1)
        );
    }
    std::sort(ids.begin(), ids.end(), [](const auto& a, const auto& b) {
        return rawstd_uuid_cmp(&a, &b) < 0;
    });

    // Every object lists on the one location its slot is on, and only there.
    size_t listed = 0;
    for (const auto& ost : store.topology()->osts()) {
        std::vector<RawstdUUID> expected;
        for (const auto& id : ids) {
            if (rawstd_uuid_cmp(
                    &store.open(id, RawstdUUID{}).chunks[0][0].ost_id, &ost.id
                ) == 0) {
                expected.push_back(id);
            }
        }
        for (unsigned int limit : {0u, 1u, 2u}) {
            std::vector<RawstdUUID> got = list_on(store, ost.location, limit);
            ASSERT_EQ(got.size(), expected.size()) << "limit " << limit;
            for (size_t i = 0; i < got.size(); ++i) {
                EXPECT_EQ(rawstd_uuid_cmp(&got[i], &expected[i]), 0);
            }
        }
        listed += expected.size();
    }
    EXPECT_EQ(listed, ids.size());
}

TEST_F(ObjectStoreTest, list_objects_on_a_location_counts_version_members) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    ObjectMap map = store.open(id, RawstdUUID{});
    RawstdUUID slot_ost = map.chunks[0][0].ost_id;
    // A location that holds no slot of the object, but one of its versions.
    RawstdUUID other{};
    for (const auto& ost : store.topology()->osts()) {
        if (rawstd_uuid_cmp(&ost.id, &slot_ost) != 0) {
            other = ost.id;
            break;
        }
    }
    ASSERT_FALSE(rawstd_uuid_is_nil(&other));
    const std::string slot_location = location_of(store, slot_ost);
    const std::string other_location = location_of(store, other);
    EXPECT_TRUE(list_on(store, other_location, 0).empty());

    RawstdUUID version_id = make_id();
    store.commit_version(
        make_id(), id, version_id, std::vector<VersionMember>{{0, other}}
    );
    ASSERT_EQ(list_on(store, other_location, 0).size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&list_on(store, other_location, 0)[0], &id), 0);
    EXPECT_EQ(list_on(store, slot_location, 0).size(), 1u);
    // A trailing '/' does not make another location.
    EXPECT_EQ(list_on(store, slot_location + "/", 0).size(), 1u);

    // Once the version is gone nothing is held there.
    store.remove_version(make_id(), id, version_id);
    EXPECT_TRUE(list_on(store, other_location, 0).empty());
}

// A location is told by its URI as a URI prints: the password of its user
// information is not part of it, in the topology or in the request.
TEST_F(ObjectStoreTest, list_objects_on_a_location_ignores_a_password) {
    TopologyOST ost = make_ost("00000000-0000-7000-8000-000000000001", "host1");
    ost.location = "ost://user:secret@host1:7777";
    ObjectStore store(dir.db_path());
    store.register_ost(registration_of(ost));
    store.create(
        RawstdUUID{}, RawstdUUID{}, make_id(), chunk_size, chunk_size,
        make_policy(1)
    );
    for (const char* location :
         {"ost://user@host1:7777", "ost://user:secret@host1:7777",
          "ost://user:another@host1:7777", "ost://user@host1:7777/"}) {
        EXPECT_EQ(list_on(store, location, 0).size(), 1u) << location;
    }
}

TEST_F(ObjectStoreTest, list_objects_on_an_unknown_location_is_enoent) {
    ObjectStore& store = make_store();
    RawstdUUID token{};
    try {
        store.list_chunks(RawstdUUID{}, token, 0, "ost://nowhere:7777");
        FAIL() << "expected ENOENT";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOENT);
    }
}

TEST_F(ObjectStoreTest, list_versions_oldest_first) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    ObjectMap live = store.open(id, RawstdUUID{});
    std::vector<VersionMember> members;
    for (const auto& slot : live.chunks[0]) {
        members.push_back(VersionMember{0, slot.ost_id});
    }

    EXPECT_TRUE(store.list_versions(id).empty());

    RawstdUUID first = make_id();
    RawstdUUID second = make_id();
    // Committed newest first: the listing still comes back oldest first.
    store.commit_version(RawstdUUID{}, id, second, members);
    store.commit_version(RawstdUUID{}, id, first, members);

    std::vector<RawstdUUID> versions = store.list_versions(id);
    ASSERT_EQ(versions.size(), 2u);
    EXPECT_EQ(rawstd_uuid_cmp(&versions[0], &first), 0);
    EXPECT_EQ(rawstd_uuid_cmp(&versions[1], &second), 0);

    try {
        store.list_versions(make_id());
        ADD_FAILURE() << "list_versions() of an unknown object succeeded";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOENT);
    }
}

TEST_F(ObjectStoreTest, commit_version_rejects_nil_version_id) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    EXPECT_THROW(
        store.commit_version(RawstdUUID{}, id, RawstdUUID{}, {}),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, commit_version_rejects_uncovered_chunk) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, 2 * chunk_size, chunk_size,
        make_policy(1)
    );
    ObjectMap live = store.open(id, RawstdUUID{});

    // Only chunk 0's own member -- chunk 1 is left uncovered.
    std::vector<VersionMember> members{
        VersionMember{0, live.chunks[0][0].ost_id},
    };

    EXPECT_THROW(
        store.commit_version(RawstdUUID{}, id, make_id(), members),
        std::system_error
    );
}

TEST_F(ObjectStoreTest, commit_version_freezes_size_across_a_later_resize) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID version_id = make_id();
    store.commit_version(
        RawstdUUID{}, id, version_id,
        {VersionMember{0, live.chunks[0][0].ost_id}}
    );

    store.resize(RawstdUUID{}, id, 3 * chunk_size);

    ObjectMap version_map = store.open(id, version_id);
    EXPECT_EQ(version_map.descriptor.logical_size, chunk_size);
    EXPECT_EQ(version_map.chunks.size(), 1u);
}

TEST_F(ObjectStoreTest, remove_version_returns_members_and_unregisters) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    ObjectMap live = store.open(id, RawstdUUID{});
    RawstdUUID version_id = make_id();
    RawstdUUID ost_id = live.chunks[0][0].ost_id;
    store.commit_version(
        RawstdUUID{}, id, version_id, {VersionMember{0, ost_id}}
    );

    std::vector<VersionMember> removed =
        store.remove_version(RawstdUUID{}, id, version_id);

    ASSERT_EQ(removed.size(), 1u);
    EXPECT_EQ(removed[0].logical_index, 0u);
    EXPECT_EQ(rawstd_uuid_cmp(&removed[0].ost_id, &ost_id), 0);
    EXPECT_THROW(store.open(id, version_id), std::system_error);
}

TEST_F(ObjectStoreTest, remove_version_rejects_unknown_version) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    EXPECT_THROW(
        store.remove_version(RawstdUUID{}, id, make_id()), std::system_error
    );
}

RawstorObjectMeta make_meta(uint64_t size, unsigned width) {
    RawstorObjectMeta meta{};
    meta.spec.size = size;
    meta.spec.width = width;
    meta.spec.chunk_size = chunk_size;
    meta.member_role = RAWSTOR_MEMBER_DATA;
    return meta;
}

TEST_F(ObjectStoreTest, reconstruct_rebuilds_single_chunk_object) {
    ObjectStore& store = make_store();
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
    ObjectStore& store = make_store();
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
    ObjectStore& store = make_store();
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
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();

    // Chunk 1 (offset chunk_size) never shows up in any record.
    std::vector<ScanRecord> records{
        ScanRecord{make_id(), id, 0, make_meta(chunk_size, 1)},
        ScanRecord{make_id(), id, 2 * chunk_size, make_meta(chunk_size, 1)},
    };

    EXPECT_THROW(store.reconstruct(records), std::system_error);
}

TEST_F(ObjectStoreTest, reconstruct_fails_on_conflicting_identity) {
    ObjectStore& store = make_store();
    RawstdUUID id = make_id();

    std::vector<ScanRecord> records{
        ScanRecord{make_id(), id, 0, make_meta(chunk_size, 1)},
        ScanRecord{make_id(), id, 0, make_meta(chunk_size, 2)},
    };

    EXPECT_THROW(store.reconstruct(records), std::system_error);
}

TEST_F(ObjectStoreTest, reconstruct_replaces_every_existing_object) {
    ObjectStore& store = make_store();
    RawstdUUID stale_id = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, stale_id, chunk_size, chunk_size,
        make_policy(1)
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

// Samples are kept in the store; availability is not: after a restart every
// OST is unavailable until it registers again.
TEST_F(ObjectStoreTest, samples_survive_a_restart_and_availability_does_not) {
    Topology topology = make_topology();
    const TopologyOST& first = topology.osts()[0];
    const TopologyOST& second = topology.osts()[1];
    {
        ObjectStore store(dir.db_path());
        RawstorLocationInfo a{10, 100}, b{20, 200};
        store.register_ost(registration_of(first, &a));
        store.register_ost(registration_of(second, &b));
        // A registration without a sample keeps the one there is.
        store.register_ost(registration_of(first));
        EXPECT_EQ(store.info().used, 30u);
        EXPECT_EQ(store.info().total, 300u);
    }
    ObjectStore reopened(dir.db_path());
    EXPECT_FALSE(reopened.backend_available(first.id));
    EXPECT_FALSE(reopened.backend_available(second.id));
    EXPECT_EQ(reopened.info().used, 30u);
    EXPECT_EQ(reopened.info().total, 300u);
}

TEST_F(ObjectStoreTest, unavailable_osts_are_excluded_from_create_and_resize) {
    ObjectStore& store = make_store();
    Topology topology = make_topology();
    for (const auto& ost : topology.osts()) {
        leave(store, ost);
    }
    EXPECT_THROW(
        store.create(
            RawstdUUID{}, {}, make_id(), chunk_size, chunk_size, make_policy(1)
        ),
        std::system_error
    );
    const auto& first = topology.osts()[0];
    const auto& second = topology.osts()[1];
    store.register_ost(registration_of(first));
    RawstdUUID id = make_id();
    store.create(RawstdUUID{}, {}, id, chunk_size, chunk_size, make_policy(1));
    auto before = store.open(id, {});
    EXPECT_EQ(rawstd_uuid_cmp(&before.chunks[0][0].ost_id, &first.id), 0);
    leave(store, first);
    EXPECT_THROW(store.resize({}, id, 2 * chunk_size), std::system_error);
    EXPECT_EQ(store.open(id, {}).descriptor.logical_size, chunk_size);
    store.register_ost(registration_of(second));
    store.resize({}, id, 2 * chunk_size);
    auto after = store.open(id, {});
    EXPECT_EQ(rawstd_uuid_cmp(&after.chunks[0][0].ost_id, &first.id), 0);
    EXPECT_EQ(rawstd_uuid_cmp(&after.chunks[1][0].ost_id, &second.id), 0);
    EXPECT_THROW(
        store.create(
            RawstdUUID{}, {}, make_id(), chunk_size, chunk_size, make_policy(2)
        ),
        std::system_error
    );
}

TEST_F(
    ObjectStoreTest, info_preserves_unsigned_counts_and_rejects_sum_overflow
) {
    ObjectStore& store = make_store();
    Topology topology = make_topology();
    RawstorLocationInfo sample{UINT64_MAX - 1, UINT64_MAX};
    store.register_ost(registration_of(topology.osts()[0], &sample));
    EXPECT_EQ(store.info().total, UINT64_MAX);
    RawstorLocationInfo more{2, 2};
    store.register_ost(registration_of(topology.osts()[1], &more));
    EXPECT_THROW(store.info(), std::system_error);
}

} // namespace

TEST_F(
    ObjectStoreTest, witness_records_are_durable_and_independent_of_object_map
) {
    RawstdUUID id = make_id();
    RawstorObjectSpec spec{};
    spec.size = chunk_size;
    spec.width = 2;
    spec.chunk_size = chunk_size;
    RawstorObjectConfig config{};
    config.epoch = 7;
    config.sync_id = 123;
    config.resync_owner = 456;
    config.sync_id_history[0] = 42;
    config.nroles = 3;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    config.roles[1] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    config.roles[2] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    {
        ObjectStore& store = make_store();
        store.create_witness(RawstdUUID{}, id, chunk_size, spec);
        bool ok = false;
        store.sync_accept(id, chunk_size, {1, 1}, {}, config, ok);
        EXPECT_TRUE(ok);
        EXPECT_THROW(
            store.create_witness(RawstdUUID{}, id, chunk_size, spec),
            std::system_error
        );
        EXPECT_THROW(store.witness_meta(id, 0), std::system_error);
        EXPECT_THROW(store.open(id, RawstdUUID{}), std::system_error);
    }
    ObjectStore& store = make_store();
    store.reconstruct({});
    auto meta = store.witness_meta(id, chunk_size);
    EXPECT_EQ(meta.member_role, RAWSTOR_MEMBER_WITNESS);
    EXPECT_EQ(meta.spec.size, spec.size);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(meta.config.sync_id, config.sync_id);
    EXPECT_EQ(meta.config.resync_owner, config.resync_owner);
    EXPECT_EQ(meta.config.sync_id_history[0], 42u);
    EXPECT_EQ(meta.config.roles[0], RAWSTOR_OBJECT_MEMBER_IN_SYNC);
    store.remove_witness(id, chunk_size);
    EXPECT_THROW(store.witness_meta(id, chunk_size), std::system_error);
}

TEST_F(
    ObjectStoreTest, witness_listing_pages_objects_without_splitting_chunks
) {
    ObjectStore& store = make_store();
    auto first = make_id();
    auto second = make_id();
    if (rawstd_uuid_cmp(&first, &second) > 0) {
        std::swap(first, second);
    }
    RawstorObjectSpec spec{};
    spec.width = 2;
    spec.chunk_size = chunk_size;
    store.create_witness(RawstdUUID{}, first, 0, spec);
    store.create_witness(RawstdUUID{}, first, chunk_size, spec);
    store.create_witness(RawstdUUID{}, second, 0, spec);
    RawstdUUID token{};
    auto entries = store.list_chunks(RawstdUUID{}, token, 1);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(rawstd_uuid_cmp(&entries[0].id, &first), 0);
    EXPECT_EQ(entries[0].offset, 0u);
    EXPECT_EQ(entries[0].type, RAWSTOR_LIST_ENTRY_CHUNK);
    EXPECT_EQ(entries[1].offset, chunk_size);
    EXPECT_EQ(entries[1].type, RAWSTOR_LIST_ENTRY_CHUNK);
    EXPECT_EQ(rawstd_uuid_cmp(&token, &first), 0);
    entries = store.list_chunks(RawstdUUID{}, token, 1);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&entries[0].id, &second), 0);
    EXPECT_TRUE(rawstd_uuid_is_nil(&token));
}

TEST_F(ObjectStoreTest, list_chunks_merges_objects_and_native_members) {
    ObjectStore& store = make_store();
    auto object = make_id();
    auto witness = make_id();
    store.create(
        RawstdUUID{}, RawstdUUID{}, object, chunk_size, chunk_size,
        make_policy(1)
    );
    // A reconstructed object map can also index a native member's id.
    store.create(
        RawstdUUID{}, RawstdUUID{}, witness, chunk_size, chunk_size,
        make_policy(1)
    );
    RawstorObjectSpec spec{};
    spec.width = 2;
    spec.chunk_size = chunk_size;
    store.create_witness(RawstdUUID{}, witness, 0, spec);
    store.create_witness(RawstdUUID{}, witness, chunk_size, spec);
    RawstdUUID token{};
    auto entries = store.list_chunks(RawstdUUID{}, token, 1);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&entries[0].id, &object), 0);
    EXPECT_EQ(entries[0].offset, 0u);
    EXPECT_EQ(entries[0].type, RAWSTOR_LIST_ENTRY_OBJECT);
    EXPECT_EQ(rawstd_uuid_cmp(&token, &object), 0);
    entries = store.list_chunks(RawstdUUID{}, token, 1);
    ASSERT_EQ(entries.size(), 3u);
    EXPECT_EQ(rawstd_uuid_cmp(&entries[0].id, &witness), 0);
    EXPECT_EQ(entries[0].type, RAWSTOR_LIST_ENTRY_OBJECT);
    EXPECT_EQ(entries[1].offset, 0u);
    EXPECT_EQ(entries[1].type, RAWSTOR_LIST_ENTRY_CHUNK);
    EXPECT_EQ(entries[2].offset, chunk_size);
    EXPECT_EQ(entries[2].type, RAWSTOR_LIST_ENTRY_CHUNK);
    EXPECT_TRUE(rawstd_uuid_is_nil(&token));
}

TEST_F(ObjectStoreTest, witness_refuses_a_ballot_beyond_its_reach) {
    RawstdUUID id = make_id();
    RawstorObjectSpec spec{};
    spec.size = chunk_size;
    spec.width = 2;
    spec.chunk_size = chunk_size;
    ObjectStore& store = make_store();
    store.create_witness(RawstdUUID{}, id, 0, spec);

    // A request moves the counters forward by a bounded amount only, so that
    // a peer cannot exhaust the counter space.
    const uint64_t jump = uint64_t(1) << 28;
    bool ok = false;
    RawstorObjectConfig config{};
    EXPECT_THROW(
        store.sync_prepare(id, 0, {jump + 1, 1}, ok), std::system_error
    );
    EXPECT_THROW(
        store.sync_accept(id, 0, {jump + 1, 1}, {}, config, ok),
        std::system_error
    );
    EXPECT_THROW(
        store.sync_accept(id, 0, {1, 1}, {jump + 1, 1}, config, ok),
        std::system_error
    );
    EXPECT_EQ(store.witness_meta(id, 0).promised.counter, 0u);

    store.sync_prepare(id, 0, {jump, 1}, ok);
    EXPECT_TRUE(ok);
    EXPECT_EQ(store.witness_meta(id, 0).promised.counter, jump);
}

TEST_F(ObjectStoreTest, witness_votes_in_the_configuration_register) {
    RawstdUUID id = make_id();
    RawstorObjectSpec spec{};
    spec.size = chunk_size;
    spec.width = 2;
    spec.chunk_size = chunk_size;
    RawstorObjectConfig config{};
    config.epoch = 8;
    config.sync_id = 9;
    config.nroles = 3;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    config.roles[1] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    config.roles[2] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    RawstorObjectBallot low{1, 5};
    RawstorObjectBallot high{4, 5};
    bool ok = false;
    {
        ObjectStore& store = make_store();
        EXPECT_THROW(store.sync_prepare(id, 0, low, ok), std::system_error);
        store.create_witness(RawstdUUID{}, id, 0, spec);

        auto meta = store.sync_prepare(id, 0, high, ok);
        EXPECT_TRUE(ok);
        EXPECT_EQ(meta.promised.counter, 4u);

        // A ballot below the promise is refused and the record shows why.
        meta = store.sync_accept(id, 0, low, {}, config, ok);
        EXPECT_FALSE(ok);
        EXPECT_EQ(meta.promised.counter, 4u);
        EXPECT_EQ(meta.config.epoch, 0u);

        meta = store.sync_accept(id, 0, high, {5, 5}, config, ok);
        EXPECT_TRUE(ok);
        EXPECT_EQ(meta.accepted.counter, 4u);
        EXPECT_EQ(meta.promised.counter, 5u);

        // Already accepted: a prepare at the same ballot is refused.
        store.sync_prepare(id, 0, high, ok);
        EXPECT_FALSE(ok);
    }
    // Promises and the accepted value survive a restart.
    ObjectStore& store = make_store();
    store.reconstruct({});
    auto meta = store.witness_meta(id, 0);
    EXPECT_EQ(meta.promised.counter, 5u);
    EXPECT_EQ(meta.accepted.counter, 4u);
    EXPECT_EQ(meta.config.epoch, 8u);
    EXPECT_EQ(meta.config.roles[1], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
}

// The witness the MDS hosts itself is a witness candidate, always available,
// and holds no storage.
TEST_F(
    ObjectStoreTest,
    the_local_witness_is_a_witness_candidate_and_counts_no_capacity
) {
    Topology topology = make_topology();
    auto mds = make_ost("00000000-0000-7000-8000-000000000004", "host4");
    mds.location = "ost://127.0.0.1:7776";
    mds.roles = {rawstor::mdsserver::Role::Witness};
    ObjectStore store(dir.db_path());
    RawstorLocationInfo info{.used = 10, .total = 100};
    register_all(store, topology, &info);
    leave(store, topology.osts()[2]);
    EXPECT_EQ(store.info().total, 200u);
    // Two DATA copies and their witness need three domains.
    EXPECT_THROW(
        store.create(
            RawstdUUID{}, {}, make_id(), chunk_size, chunk_size, make_policy(2)
        ),
        std::system_error
    );

    store.set_local_witness(mds);
    EXPECT_TRUE(store.backend_available(mds.id));
    EXPECT_EQ(store.info().total, 200u);
    EXPECT_EQ(store.info().used, 20u);
    auto id = make_id();
    store.create(RawstdUUID{}, {}, id, chunk_size, chunk_size, make_policy(2));
    ASSERT_EQ(store.open(id, {}).chunks.front().size(), 3u);
    EXPECT_EQ(
        rawstd_uuid_cmp(
            &store.open(id, {}).chunks.front().back().ost_id, &mds.id
        ),
        0
    );
    // Nobody registers under its id.
    EXPECT_EQ(
        errno_of([&] { store.register_ost(registration_of(mds)); }), EEXIST
    );
}

// ---- accounts (docs/accounts.md) ----

TEST_F(ObjectStoreTest, an_object_is_owned_by_the_account_that_created_it) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();
    store.create_account(RawstdUUID{}, acme);
    RawstdUUID owned = make_id();
    RawstdUUID unowned = make_id();

    store.create(
        acme, RawstdUUID{}, owned, chunk_size, chunk_size, make_policy(1)
    );
    store.create(
        RawstdUUID{}, RawstdUUID{}, unowned, chunk_size, chunk_size,
        make_policy(1)
    );

    // Owned or not, an object is addressed by its id alone.
    store.open(owned, RawstdUUID{});
    store.open(unowned, RawstdUUID{});
    // And an id is unique: the same id for another owner is a duplicate.
    EXPECT_EQ(
        errno_of([&] {
            store.create(
                RawstdUUID{}, RawstdUUID{}, owned, chunk_size, chunk_size,
                make_policy(1)
            );
        }),
        EEXIST
    );
}

TEST_F(ObjectStoreTest, listing_shows_the_objects_a_account_owns) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();
    RawstdUUID other = make_id();
    store.create_account(RawstdUUID{}, acme);
    store.create_account(RawstdUUID{}, other);
    RawstdUUID in_acme = make_id();
    RawstdUUID in_other = make_id();
    RawstdUUID in_none = make_id();
    store.create(
        acme, RawstdUUID{}, in_acme, chunk_size, chunk_size, make_policy(1)
    );
    store.create(
        other, RawstdUUID{}, in_other, chunk_size, chunk_size, make_policy(1)
    );
    store.create(
        RawstdUUID{}, RawstdUUID{}, in_none, chunk_size, chunk_size,
        make_policy(1)
    );

    RawstdUUID token{};
    auto entries = store.list_chunks(acme, token, 0);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&entries[0].id, &in_acme), 0);

    // An administrator names no account and sees every object.
    token = {};
    auto all = store.list_chunks(RawstdUUID{}, token, 0);
    ASSERT_EQ(all.size(), 3u);

    // Every entry names the owner of its object, whoever asked.
    for (const auto& entry : all) {
        const RawstdUUID& owner =
            rawstd_uuid_cmp(&entry.id, &in_acme) == 0    ? acme
            : rawstd_uuid_cmp(&entry.id, &in_other) == 0 ? other
                                                         : RawstdUUID{};
        EXPECT_EQ(rawstd_uuid_cmp(&entry.account, &owner), 0);
    }

    // An account that owns nothing sees nothing.
    token = {};
    EXPECT_TRUE(store.list_chunks(make_id(), token, 0).empty());
}

TEST_F(ObjectStoreTest, an_owner_is_a_registered_account) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();

    EXPECT_EQ(
        errno_of([&] {
            store.create(
                acme, RawstdUUID{}, make_id(), chunk_size, chunk_size,
                make_policy(1)
            );
        }),
        ENOENT
    );

    store.create_account(RawstdUUID{}, acme);
    store.create(
        acme, RawstdUUID{}, make_id(), chunk_size, chunk_size, make_policy(1)
    );
}

// A page ends where the next one starts: every account once, in order, and no
// token after the last page; limit 0 is everything.
TEST_F(ObjectStoreTest, accounts_are_listed_a_page_at_a_time) {
    ObjectStore& store = make_store();
    for (int i = 0; i < 4; ++i) {
        store.create_account(RawstdUUID{}, make_id());
    }

    std::vector<RawstdUUID> paged = all_accounts(store, 2);
    ASSERT_EQ(paged.size(), 5u);
    for (size_t i = 1; i < paged.size(); ++i) {
        EXPECT_LT(rawstd_uuid_cmp(&paged[i - 1], &paged[i]), 0);
    }

    RawstdUUID token{};
    std::vector<RawstdUUID> page = store.list_accounts(token, 0);
    EXPECT_EQ(page.size(), 5u);
    EXPECT_TRUE(rawstd_uuid_is_nil(&token));

    token = {};
    page = store.list_accounts(token, 2);
    EXPECT_EQ(page.size(), 2u);
    EXPECT_EQ(rawstd_uuid_cmp(&token, &page.back()), 0);
}

// A transfer moves the object between accounts: listings follow it, the old
// owner can then be removed, and the new one must be registered.
TEST_F(ObjectStoreTest, an_object_is_transferred_to_another_account) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();
    RawstdUUID other = make_id();
    store.create_account(RawstdUUID{}, acme);
    store.create_account(RawstdUUID{}, other);
    RawstdUUID id = make_id();
    store.create(
        acme, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    EXPECT_EQ(
        errno_of([&] { store.transfer(RawstdUUID{}, id, RawstdUUID{}); }),
        EINVAL
    );
    EXPECT_EQ(
        errno_of([&] { store.transfer(RawstdUUID{}, id, make_id()); }), ENOENT
    );
    EXPECT_EQ(
        errno_of([&] { store.transfer(RawstdUUID{}, make_id(), other); }),
        ENOENT
    );
    EXPECT_EQ(
        errno_of([&] { store.remove_account(RawstdUUID{}, acme); }), EBUSY
    );

    store.transfer(RawstdUUID{}, id, other);
    // Idempotent.
    store.transfer(RawstdUUID{}, id, other);

    RawstdUUID token{};
    EXPECT_EQ(store.list_chunks(other, token, 0).size(), 1u);
    token = {};
    EXPECT_TRUE(store.list_chunks(acme, token, 0).empty());
    store.remove_account(RawstdUUID{}, acme);
}

// A transfer resent after a lost reply is answered, not applied again: it
// does not undo what was transferred since.
TEST_F(ObjectStoreTest, a_replayed_transfer_does_not_undo_a_later_one) {
    ObjectStore& store = make_store();
    RawstdUUID first = make_id();
    RawstdUUID second = make_id();
    store.create_account(RawstdUUID{}, first);
    store.create_account(RawstdUUID{}, second);
    RawstdUUID id = make_id();
    store.create(
        first, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    RawstdUUID key = make_id();

    RawstdUUID applied = store.transfer(key, id, second);
    EXPECT_EQ(rawstd_uuid_cmp(&applied, &second), 0);
    store.transfer(make_id(), id, first);

    // The repeat applies nothing and reports who owns the object now.
    RawstdUUID now = store.transfer(key, id, second);
    EXPECT_EQ(rawstd_uuid_cmp(&now, &first), 0);

    RawstdUUID token{};
    EXPECT_EQ(store.list_chunks(first, token, 0).size(), 1u);
    token = {};
    EXPECT_TRUE(store.list_chunks(second, token, 0).empty());

    // The key belongs to that request: another object with it is refused.
    EXPECT_EQ(
        errno_of([&] { store.transfer(key, make_id(), second); }), EINVAL
    );
}

// resize reports the owner of the object, which the chunks it adds are
// created for.
TEST_F(ObjectStoreTest, resize_reports_the_owner) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();
    RawstdUUID other = make_id();
    store.create_account(RawstdUUID{}, acme);
    store.create_account(RawstdUUID{}, other);
    RawstdUUID id = make_id();
    store.create(
        acme, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );

    ResizeResult grown = store.resize(RawstdUUID{}, id, 2 * chunk_size);
    EXPECT_EQ(rawstd_uuid_cmp(&grown.account, &acme), 0);

    store.transfer(RawstdUUID{}, id, other);
    grown = store.resize(RawstdUUID{}, id, 3 * chunk_size);
    EXPECT_EQ(rawstd_uuid_cmp(&grown.account, &other), 0);

    // A repeat applies nothing and reports the owner as it is then.
    RawstdUUID key = make_id();
    ResizeResult first = store.resize(key, id, 4 * chunk_size);
    EXPECT_EQ(rawstd_uuid_cmp(&first.account, &other), 0);
    store.transfer(RawstdUUID{}, id, acme);
    ResizeResult again = store.resize(key, id, 4 * chunk_size);
    EXPECT_EQ(again.old_nchunks, first.old_nchunks);
    EXPECT_EQ(rawstd_uuid_cmp(&again.account, &acme), 0);
}

TEST_F(ObjectStoreTest, accounts_are_created_and_removed) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();

    // The default account is registered with every store, and stays.
    ASSERT_EQ(all_accounts(store).size(), 1u);
    RawstdUUID default_account = all_accounts(store).front();
    EXPECT_EQ(
        errno_of([&] { store.create_account(RawstdUUID{}, default_account); }),
        EEXIST
    );
    EXPECT_EQ(
        errno_of([&] { store.remove_account(RawstdUUID{}, default_account); }),
        EPERM
    );
    EXPECT_EQ(
        errno_of([&] { store.create_account(RawstdUUID{}, RawstdUUID{}); }),
        EINVAL
    );

    store.create_account(RawstdUUID{}, acme);
    EXPECT_EQ(all_accounts(store).size(), 2u);
    EXPECT_EQ(
        errno_of([&] { store.create_account(RawstdUUID{}, acme); }), EEXIST
    );

    // An account that owns an object is not removed; one that owns none is.
    RawstdUUID id = make_id();
    store.create(
        acme, RawstdUUID{}, id, chunk_size, chunk_size, make_policy(1)
    );
    EXPECT_EQ(
        errno_of([&] { store.remove_account(RawstdUUID{}, acme); }), EBUSY
    );
    store.remove(RawstdUUID{}, id);
    store.remove_account(RawstdUUID{}, acme);
    EXPECT_EQ(all_accounts(store).size(), 1u);
    EXPECT_EQ(
        errno_of([&] { store.remove_account(RawstdUUID{}, acme); }), ENOENT
    );
}

// A retried ACCOUNT_CREATE answers from its record, but an account removed
// since is registered again instead of being reported created and left missing.
TEST_F(
    ObjectStoreTest, a_replayed_account_creation_restores_a_removed_account
) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();
    RawstdUUID key = make_id();

    store.create_account(key, acme);
    store.remove_account(RawstdUUID{}, acme);
    EXPECT_EQ(all_accounts(store).size(), 1u);

    store.create_account(key, acme);
    EXPECT_EQ(all_accounts(store).size(), 2u);
    store.create(
        acme, RawstdUUID{}, make_id(), chunk_size, chunk_size, make_policy(1)
    );

    // Replayed again while it exists: still just the one account.
    store.create_account(key, acme);
    EXPECT_EQ(all_accounts(store).size(), 2u);
}

// The owner is part of the chunk's own metadata, so a rebuilt map has it.
TEST_F(ObjectStoreTest, reconstruct_restores_the_owner) {
    ObjectStore& store = make_store();
    RawstdUUID acme = make_id();
    RawstdUUID id = make_id();
    RawstdUUID ost_id = make_id();

    RawstorObjectMeta meta = make_meta(chunk_size, 1);
    memcpy(meta.account_id, acme.bytes, sizeof(meta.account_id));
    std::vector<ScanRecord> records{ScanRecord{ost_id, id, 0, meta}};
    store.reconstruct(records);

    // The account is registered again, and owns the object.
    ASSERT_EQ(all_accounts(store).size(), 2u);
    RawstdUUID token{};
    auto entries = store.list_chunks(acme, token, 0);
    ASSERT_EQ(entries.size(), 1u);
    EXPECT_EQ(rawstd_uuid_cmp(&entries[0].id, &id), 0);
    EXPECT_EQ(
        errno_of([&] { store.remove_account(RawstdUUID{}, acme); }), EBUSY
    );
}

TEST_F(
    ObjectStoreTest,
    authorization_uses_certificate_roles_and_object_restrictions
) {
    ObjectStore& store = make_store();
    RawstdUUID account = make_id(), other = make_id(), object = make_id();
    store.create_account(make_id(), account);
    store.create_account(make_id(), other);
    store.create(
        account, make_id(), object, chunk_size, chunk_size, make_policy(1)
    );
    RawstdUUIDString account_text;
    rawstd_uuid_to_string(&account, &account_text);
    std::string identity = std::string("spiffe://cluster.example/account/") +
                           account_text + "/client/user";
    rawtls::SpiffeId peer(identity);
    auto error = [&](int expected, auto call) {
        try {
            call();
            FAIL() << "expected error " << expected;
        } catch (const std::system_error& e) {
            EXPECT_EQ(e.code().value(), expected);
        }
    };
    error(EACCES, [&] { store.authorize(&peer, RAWSTOR_CMD_RESOLVE, object); });
    peer.permissions({RAWSTOR_ROLE_READER, {}});
    EXPECT_EQ(
        store.authorize(&peer, RAWSTOR_CMD_RESOLVE, object).permissions,
        RAWSTOR_PERM_READ
    );
    error(EACCES, [&] {
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object);
    });
    error(ENOENT, [&] {
        store.authorize(&peer, RAWSTOR_CMD_OBJ_CREATE, {}, other);
    });
    error(EACCES, [&] { store.authorize(&peer, RAWSTOR_CMD_ACCOUNT_CREATE); });
    peer.permissions({RAWSTOR_ROLE_MANAGER, {}});
    EXPECT_EQ(
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object).permissions,
        RAWSTOR_PERM_ALL
    );
    RawstdUUID foreign = make_id(), unowned = make_id();
    store.create(
        other, make_id(), foreign, chunk_size, chunk_size, make_policy(1)
    );
    store.create(
        {}, make_id(), unowned, chunk_size, chunk_size, make_policy(1)
    );
    error(ENOENT, [&] {
        store.authorize(&peer, RAWSTOR_CMD_OBJ_CREATE, foreign, account);
    });
    error(ENOENT, [&] {
        store.authorize(&peer, RAWSTOR_CMD_OBJ_CREATE, unowned, account);
    });
    error(ENOENT, [&] { store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE); });
    RawstdUUIDString object_text;
    rawstd_uuid_to_string(&object, &object_text);
    peer.permissions(
        {RAWSTOR_ROLE_MANAGER, {{object_text, RAWSTOR_PERM_READ}}}
    );
    error(EACCES, [&] {
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object);
    });
    EXPECT_EQ(
        store.authorize(&peer, RAWSTOR_CMD_RESOLVE, object).permissions,
        RAWSTOR_PERM_READ
    );
    store.transfer(make_id(), object, other);
    error(ENOENT, [&] { store.authorize(&peer, RAWSTOR_CMD_RESOLVE, object); });
    peer.permissions({});
    error(EACCES, [&] { store.authorize(&peer, RAWSTOR_CMD_LIST); });
}

TEST_F(
    ObjectStoreTest, a_account_can_authorize_only_its_own_recorded_remove_retry
) {
    ObjectStore& store = make_store();
    RawstdUUID account = make_id(), object = make_id(), mutation = make_id();
    store.create_account(make_id(), account);
    RawstdUUIDString text;
    rawstd_uuid_to_string(&account, &text);
    std::string identity = std::string("spiffe://cluster.example/account/") +
                           text + "/client/manager";
    rawtls::SpiffeId peer(identity);
    peer.permissions({RAWSTOR_ROLE_MANAGER, {}});
    store.create(
        account, make_id(), object, chunk_size, chunk_size, make_policy(1)
    );
    store.remove(mutation, object);
    EXPECT_NO_THROW(
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object, {}, mutation)
    );
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object, {}, make_id()),
        std::system_error
    );
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_RESOLVE, object), std::system_error
    );
    peer.permissions({});
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object, {}, mutation),
        std::system_error
    );
}

TEST_F(
    ObjectStoreTest, witness_authorization_uses_certificate_policy_and_owner
) {
    ObjectStore& store = make_store();
    RawstdUUID account = make_id(), foreign = make_id(), object = make_id();
    RawstdUUIDString text;
    rawstd_uuid_to_string(&account, &text);
    rawtls::SpiffeId peer(
        std::string("spiffe://cluster.example/account/") + text +
        "/client/writer"
    );
    peer.permissions({RAWSTOR_ROLE_MANAGER, {}});
    RawstorObjectSpec spec{};
    spec.size = chunk_size;
    spec.chunk_size = chunk_size;
    spec.width = 2;
    store.create_witness(foreign, object, 0, spec);
    EXPECT_THROW(
        store.authorize_witness(&peer, RAWSTOR_CMD_META, object, 0),
        std::system_error
    );
    EXPECT_THROW(
        store.authorize_witness(
            &peer, RAWSTOR_CMD_ALLOCATE, object, 0, account
        ),
        std::system_error
    );
    store.remove_witness(object, 0);
    EXPECT_NO_THROW(
        store.authorize_witness(&peer, RAWSTOR_CMD_ALLOCATE, object, 0, account)
    );
    EXPECT_THROW(
        store.authorize_witness(
            &peer, RAWSTOR_CMD_ALLOCATE, object, 0, foreign
        ),
        std::system_error
    );
    store.create_witness(account, object, 0, spec);
    EXPECT_NO_THROW(
        store.authorize_witness(&peer, RAWSTOR_CMD_META, object, 0)
    );
    peer.permissions({RAWSTOR_ROLE_READER, {}});
    EXPECT_THROW(
        store.authorize_witness(&peer, RAWSTOR_CMD_SYNC_ACCEPT, object, 0),
        std::system_error
    );
    EXPECT_THROW(
        store.authorize_witness(&peer, RAWSTOR_CMD_RELEASE, object, 0),
        std::system_error
    );
}

TEST_F(
    ObjectStoreTest,
    none_can_resolve_only_granted_objects_without_listing_account
) {
    ObjectStore& store = make_store();
    RawstdUUID account = make_id(), object = make_id(), other = make_id();
    store.create_account(make_id(), account);
    for (const auto& id : {object, other}) {
        store.create(
            account, make_id(), id, chunk_size, chunk_size, make_policy(1)
        );
    }
    RawstdUUIDString account_text, object_text;
    rawstd_uuid_to_string(&account, &account_text);
    rawstd_uuid_to_string(&object, &object_text);
    rawtls::SpiffeId peer(
        std::string("spiffe://cluster.example/account/") + account_text +
        "/client/vhost"
    );
    peer.permissions({RAWSTOR_ROLE_NONE, {{object_text, 3}}});
    EXPECT_NO_THROW(store.authorize(&peer, RAWSTOR_CMD_SET_OBJECT));
    EXPECT_EQ(
        store.authorize(&peer, RAWSTOR_CMD_RESOLVE, object).permissions, 3u
    );
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_RESOLVE, other), std::system_error
    );
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_OBJ_REMOVE, object),
        std::system_error
    );
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_OBJ_CREATE, make_id(), account),
        std::system_error
    );
    EXPECT_THROW(store.authorize(&peer, RAWSTOR_CMD_LIST), std::system_error);
    peer.permissions({RAWSTOR_ROLE_NONE, {}});
    EXPECT_THROW(
        store.authorize(&peer, RAWSTOR_CMD_SET_OBJECT), std::system_error
    );
}

// The ids of the topology's entries `store` lists, a page at a time.
std::vector<RawstdUUID>
list_locations_of(ObjectStore& store, unsigned int limit) {
    std::vector<RawstdUUID> ret;
    RawstdUUID token{};
    do {
        for (const auto& ost : store.list_locations(token, limit)) {
            ret.push_back(ost.id);
        }
    } while (!rawstd_uuid_is_nil(&token));
    return ret;
}

TEST_F(ObjectStoreTest, list_locations_pages_by_id) {
    ObjectStore& store = make_store();
    const auto& osts = store.topology()->osts();
    std::vector<RawstdUUID> expected;
    for (const auto& ost : osts) {
        expected.push_back(ost.id);
    }
    std::sort(
        expected.begin(), expected.end(),
        [](const auto& a, const auto& b) { return rawstd_uuid_cmp(&a, &b) < 0; }
    );

    for (unsigned int limit : {0u, 1u, 2u, 3u, 10u}) {
        std::vector<RawstdUUID> got = list_locations_of(store, limit);
        ASSERT_EQ(got.size(), expected.size()) << "limit " << limit;
        for (size_t i = 0; i < got.size(); ++i) {
            EXPECT_EQ(rawstd_uuid_cmp(&got[i], &expected[i]), 0);
        }
    }

    // A page that ends before the last entry reports where it ended.
    RawstdUUID token{};
    auto page = store.list_locations(token, 2);
    ASSERT_EQ(page.size(), 2u);
    EXPECT_EQ(rawstd_uuid_cmp(&token, &page.back().id), 0);
    // A page that reaches the last entry does not.
    page = store.list_locations(token, 2);
    EXPECT_EQ(page.size(), 1u);
    EXPECT_TRUE(rawstd_uuid_is_nil(&token));
}

// The topology is the operator's: an admin lists it, an account's client does
// not.
TEST_F(ObjectStoreTest, only_an_admin_lists_the_locations) {
    ObjectStore& store = make_store();
    rawtls::SpiffeId admin("spiffe://cluster.example/admin/operator");
    EXPECT_NO_THROW(store.authorize(&admin, RAWSTOR_CMD_LIST_LOCATIONS));

    RawstdUUID account = make_id();
    store.create_account(make_id(), account);
    RawstdUUIDString account_text;
    rawstd_uuid_to_string(&account, &account_text);
    rawtls::SpiffeId client(
        std::string("spiffe://cluster.example/account/") + account_text +
        "/client/user"
    );
    client.permissions({RAWSTOR_ROLE_MANAGER, {}});
    try {
        store.authorize(&client, RAWSTOR_CMD_LIST_LOCATIONS);
        FAIL() << "expected EACCES";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EACCES);
    }
}
