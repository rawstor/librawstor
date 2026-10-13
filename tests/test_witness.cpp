#include "backend.hpp"
#include "config.hpp"
#include "location.hpp"
#include "object.hpp"
#include "object_env.hpp"
#include "opts.h"
#include "slot.hpp"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <atomic>
#include <barrier>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>
#include <rawstor/rawstor.h>
#include <rawstor/target.h>
#include <string>
#include <system_error>
#include <thread>
#include <type_traits>

namespace {
template <typename T>
T run(rawio::Queue& queue, rawstd::Task<T> task) {
    while (!task.done()) {
        queue.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    if constexpr (std::is_void_v<T>) {
        task.get();
    } else {
        return task.get();
    }
}
rawstd::Task<void> pause(rawio::Queue& queue) {
    co_await queue.timeout(1000);
}

RawstdUUID new_id() {
    RawstdUUID id{};
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("uuid");
    }
    return id;
}
std::string id_string(const RawstdUUID& id) {
    RawstdUUIDString text;
    rawstd_uuid_to_string(&id, &text);
    return text;
}
class HiddenLocation {
    std::filesystem::path _path;
    std::filesystem::path _offline;

public:
    explicit HiddenLocation(const rawstor::tests::TmpDir& dir) :
        _path(dir.path()),
        _offline(dir.path().string() + "-offline") {
        std::filesystem::rename(_path, _offline);
    }
    ~HiddenLocation() { std::filesystem::rename(_offline, _path); }
};
class WitnessTest : public testing::Test {
protected:
    rawstor::tests::TmpDir a, b, w;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(128);
    RawstdUUID id = new_id();
    RawstorObjectSpec spec{};
    std::unique_ptr<rawstor::Target> target;
    std::string witness;
    void
    create(const std::string& witness_uri = "", const std::string& b_uri = "") {
        witness = witness_uri.empty() ? w.uri() : witness_uri;
        spec.size = 65536;
        spec.width = 2;
        target = std::make_unique<rawstor::Target>(std::vector<rawstd::URI>{
            rawstd::URI(a.uri() + "/" + id_string(id)),
            rawstd::URI(
                (b_uri.empty() ? b.uri() : b_uri) + "/" + id_string(id)
            ),
            rawstd::URI(witness + "/" + id_string(id))
        });
        run(*queue, target->create(*queue, spec));
    }
    void create_four(const std::string& c_uri, const std::string& d_uri) {
        witness = w.uri();
        spec.size = 65536;
        spec.width = 4;
        target = std::make_unique<rawstor::Target>(std::vector<rawstd::URI>{
            rawstd::URI(a.uri() + "/" + id_string(id)),
            rawstd::URI(b.uri() + "/" + id_string(id)),
            rawstd::URI(c_uri + "/" + id_string(id)),
            rawstd::URI(d_uri + "/" + id_string(id)),
            rawstd::URI(witness + "/" + id_string(id))
        });
        run(*queue, target->create(*queue, spec));
    }
    void write(rawstor::Object& object, const std::string& value = "hello") {
        EXPECT_EQ(
            run(*queue, object.pwrite(value.data(), value.size(), 0, false)),
            value.size()
        );
    }
    void seed() {
        auto object = run(*queue, target->open(*queue, 0));
        write(*object);
        run(*queue, object->close(true));
    }
    std::vector<RawstorObjectMeta> metas() {
        return run(*queue, target->meta(*queue, 0));
    }
    void set_member_state(
        RawstorObjectSyncStateValue state, RawstorObjectConfig config
    ) {
        auto slot =
            run(*queue, rawstor::Slot::create(*queue, rawstd::URI(witness)));
        run(*queue, slot->set_config(
                        id, 0, 2, config, rawstor::config_state_flags(state)
                    ));
        run(*queue, slot->close());
    }
    void refused() {
        try {
            auto object = run(*queue, target->open(*queue, 0));
            run(*queue, object->close(false));
            FAIL() << "unsafe open succeeded";
        } catch (const std::system_error& e) {
            EXPECT_TRUE(
                e.code().value() == ENOTCONN ||
                e.code().value() == ENOTRECOVERABLE
            ) << e.what();
        }
    }
};
} // namespace

TEST_F(WitnessTest, metadata_only_creation_and_clean_close) {
    create();
    seed();
    auto metadata = metas();
    ASSERT_EQ(metadata.size(), 3u);
    EXPECT_EQ(metadata[2].member_role, RAWSTOR_MEMBER_WITNESS);
    EXPECT_EQ(metadata[2].spec.size, 0u);
    EXPECT_EQ(metadata[2].spec.width, 2u);
    EXPECT_EQ(run(*queue, target->spec(*queue)).width, 2u);
    EXPECT_EQ(metadata[2].state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(metadata[2].config.sync_id, metadata[0].config.sync_id);
    EXPECT_NE(metadata[2].config.sync_id, 0u);
}

TEST_F(WitnessTest, clean_witness_allows_one_data_member_down) {
    create();
    seed();
    auto previous = metas()[2].config.sync_id;
    HiddenLocation offline(b);
    auto object = run(*queue, target->open(*queue, 0));
    std::string data(5, '\0');
    EXPECT_EQ(run(*queue, object->pread(data.data(), data.size(), 0)), 5u);
    EXPECT_EQ(data, "hello");
    write(*object, "newer");
    auto metadata = metas();
    EXPECT_EQ(metadata[2].state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_NE(metadata[2].config.sync_id, previous);
    EXPECT_EQ(metadata[2].config.sync_id, metadata[0].config.sync_id);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, lost_witness_abstains) {
    create();
    seed();
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_LOST, metas()[0].config);
    HiddenLocation offline(b);
    refused();
}

TEST_F(WitnessTest, degraded_witness_only_approves_recorded_survivor) {
    create();
    seed();
    auto config = metas()[0].config;
    config.roles[1] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    run(*queue, target->set_member_config(*queue, 0, 0, config, 0));
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_DIRTY, config);
    {
        HiddenLocation offline(b);
        auto object = run(*queue, target->open(*queue, 0));
        run(*queue, object->close(false));
    }
    HiddenLocation offline(a);
    refused();
}

TEST_F(WitnessTest, dirty_witness_votes_for_matching_configuration) {
    create();
    seed();
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_DIRTY, metas()[0].config);
    HiddenLocation offline(b);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    run(*queue, object->close(false));
}

TEST_F(WitnessTest, empty_witness_abstains_and_data_quorum_reattaches) {
    create();
    seed();
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_CLEAN, RawstorObjectConfig{});
    {
        HiddenLocation offline(b);
        refused();
    }
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    run(*queue, object->close(true));
    EXPECT_EQ(metas()[2].config.sync_id, metas()[0].config.sync_id);
}

TEST_F(WitnessTest, witness_newer_generation_vetoes_ancestor) {
    create();
    seed();
    auto config = metas()[0].config;
    config.sync_id_history[0] = config.sync_id;
    config.sync_id ^= 0x12345678;
    ++config.epoch;
    config.roles[1] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    run(*queue, target->set_member_config(*queue, 0, 0, config, 0));
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_DIRTY, config);
    HiddenLocation offline(a);
    refused();
}

TEST_F(WitnessTest, data_quorum_works_when_witness_is_down) {
    create();
    seed();
    HiddenLocation offline(w);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, witness_assisted_write_requires_durable_witness_update) {
    create();
    seed();
    HiddenLocation offline_b(b);
    auto object = run(*queue, target->open(*queue, 0));
    HiddenLocation offline_w(w);
    std::string value = "unsafe";
    EXPECT_THROW(
        run(*queue, object->pwrite(value.data(), value.size(), 0, false)),
        std::system_error
    );
    run(*queue, object->close(false));
}

TEST_F(WitnessTest, unclean_close_retains_dirty_configuration) {
    create();
    seed();
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    run(*queue, object->close(false));
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    HiddenLocation offline(b);
    auto reopened = run(*queue, target->open(*queue, 0));
    run(*queue, reopened->close(false));
}

TEST_F(WitnessTest, witness_alone_cannot_serve_data) {
    create();
    seed();
    HiddenLocation offline_a(a), offline_b(b);
    refused();
}

TEST_F(WitnessTest, ost_forwards_witness_creation_and_state) {
    rawstor::tests::ObjectEnv servers(29601, 29602);
    create("ost://127.0.0.1:29602");
    seed();
    EXPECT_EQ(metas()[2].spec.size, 0u);
    HiddenLocation offline(b);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, mds_stores_witness_and_votes) {
    rawstor::tests::ObjectEnv servers(29603, 29604);
    create(servers.location());
    seed();
    {
        HiddenLocation offline(b);
        auto object = run(*queue, target->open(*queue, 0));
        write(*object);
        run(*queue, object->close(true));
        EXPECT_EQ(metas()[2].member_role, RAWSTOR_MEMBER_WITNESS);
    }
    run(*queue, target->remove(*queue));
}

TEST_F(
    WitnessTest, runtime_degrade_updates_witness_and_allows_survivor_restart
) {
    auto servers = std::make_unique<rawstor::tests::ObjectEnv>(29605, 29606);
    create("", "ost://127.0.0.1:29606");
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    servers.reset();
    write(*object, "newer");
    auto metadata = metas();
    EXPECT_EQ(metadata[2].state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(metadata[2].config.sync_id, metadata[0].config.sync_id);
    EXPECT_EQ(metadata[2].config.roles[1], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    run(*queue, object->close(false));
    object = run(*queue, target->open(*queue, 0));
    std::string data(5, '\0');
    EXPECT_EQ(run(*queue, object->pread(data.data(), data.size(), 0)), 5u);
    EXPECT_EQ(data, "newer");
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, witness_quorum_recreates_missing_copy_and_resyncs) {
    create();
    seed();
    auto metadata = metas();
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(b.uri())));
    run(*queue, slot->remove(id, 0));
    run(*queue, slot->close());
    auto object = run(*queue, target->open(*queue, 0));
    write(*object, "newer");
    bool synced = false;
    for (unsigned i = 0; i < 2000; ++i) {
        metadata = metas();
        if (metadata[1].config.sync_id == metadata[0].config.sync_id &&
            metadata[1].config.roles[1] == RAWSTOR_OBJECT_MEMBER_IN_SYNC) {
            synced = true;
            break;
        }
        run(*queue, pause(*queue));
    }
    ASSERT_TRUE(synced);
    run(*queue, object->close(true));
    EXPECT_EQ(metas()[2].config.sync_id, metas()[0].config.sync_id);
    HiddenLocation offline(a);
    object = run(*queue, target->open(*queue, 0));
    std::string data(5, '\0');
    EXPECT_EQ(run(*queue, object->pread(data.data(), data.size(), 0)), 5u);
    EXPECT_EQ(data, "newer");
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, metadata_update_applies_state_and_config_to_data_member) {
    create();
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(a.uri())));
    auto config = metas()[0].config;
    ++config.epoch;
    ++config.sync_id;
    for (auto state :
         {RAWSTOR_OBJECT_SYNC_STATE_DIRTY, RAWSTOR_OBJECT_SYNC_STATE_LOST,
          RAWSTOR_OBJECT_SYNC_STATE_CLEAN}) {
        run(*queue, slot->set_config(
                        id, 0, 0, config, rawstor::config_state_flags(state)
                    ));
        auto meta = run(*queue, slot->meta(id, 0)).front();
        EXPECT_EQ(meta.member_role, RAWSTOR_MEMBER_DATA);
        EXPECT_EQ(meta.state, state);
        EXPECT_EQ(meta.config.sync_id, config.sync_id);
    }
    run(*queue, slot->close());
}

TEST_F(WitnessTest, configuration_only_update_preserves_witness_state) {
    create();
    auto config = metas()[0].config;
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_DIRTY, config);
    ++config.epoch;
    ++config.sync_id;
    run(*queue, target->set_member_config(*queue, 0, 2, config, 0));
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(metas()[2].config.sync_id, config.sync_id);
    run(*queue, target->set_member_config(
                    *queue, 0, 2, config, RAWSTOR_CONFIG_STATE_LOST
                ));
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    EXPECT_THROW(
        run(*queue, target->set_member_config(
                        *queue, 0, 2, config,
                        RAWSTOR_CONFIG_STATE_CLEAN | RAWSTOR_CONFIG_CLEAR_LOST
                    )),
        std::system_error
    );
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
}

TEST_F(WitnessTest, rejects_witness_with_odd_number_of_data_members) {
    rawstor::tests::TmpDir c;
    id = new_id();
    spec.size = 65536;
    spec.width = 3;
    witness = w.uri();
    target = std::make_unique<rawstor::Target>(std::vector<rawstd::URI>{
        rawstd::URI(a.uri() + "/" + id_string(id)),
        rawstd::URI(b.uri() + "/" + id_string(id)),
        rawstd::URI(c.uri() + "/" + id_string(id)),
        rawstd::URI(witness + "/" + id_string(id))
    });
    EXPECT_THROW(run(*queue, target->create(*queue, spec)), std::system_error);
    EXPECT_THROW(run(*queue, target->open(*queue, 0)), std::system_error);
}

TEST_F(WitnessTest, readonly_open_never_rewrites_witness) {
    create();
    seed();
    auto config = metas()[0].config;
    set_member_state(RAWSTOR_OBJECT_SYNC_STATE_LOST, config);
    auto object = run(*queue, target->open(*queue, RAWSTOR_READONLY));
    run(*queue, object->close(true));
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    EXPECT_EQ(metas()[2].config.sync_id, config.sync_id);
}

TEST_F(WitnessTest, newly_created_object_can_open_degraded_before_first_write) {
    create();
    auto previous = metas()[2].config.sync_id;
    ASSERT_NE(previous, 0u);
    HiddenLocation offline(b);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    EXPECT_NE(metas()[2].config.sync_id, previous);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, matching_location_count_creates_only_data_members) {
    spec.size = 65536;
    spec.width = 3;
    target = std::make_unique<rawstor::Target>(std::vector<rawstd::URI>{
        rawstd::URI(a.uri() + "/" + id_string(id)),
        rawstd::URI(b.uri() + "/" + id_string(id)),
        rawstd::URI(w.uri() + "/" + id_string(id))
    });
    run(*queue, target->create(*queue, spec));
    for (const auto& metadata : metas()) {
        EXPECT_EQ(metadata.member_role, RAWSTOR_MEMBER_DATA);
    }
}

TEST_F(WitnessTest, last_location_is_witness_and_does_not_supply_data_or_size) {
    create();
    EXPECT_EQ(metas()[0].member_role, RAWSTOR_MEMBER_DATA);
    EXPECT_EQ(metas()[1].member_role, RAWSTOR_MEMBER_DATA);
    EXPECT_EQ(metas()[2].member_role, RAWSTOR_MEMBER_WITNESS);
    EXPECT_EQ(run(*queue, target->spec(*queue)).size, spec.size);
    seed();
    HiddenLocation offline(b);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, witness_records_and_votes_are_per_chunk) {
    witness = w.uri();
    spec.size = 131072;
    spec.chunk_size = 65536;
    spec.width = 2;
    rawstor::Location location(
        {rawstd::URI(a.uri()), rawstd::URI(b.uri()), rawstd::URI(witness)}
    );
    target = std::make_unique<rawstor::Target>(
        run(*queue, location.create(*queue, id, spec))
    );
    HiddenLocation offline(b);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    std::string value = "second";
    EXPECT_EQ(
        run(*queue, object->pwrite(value.data(), value.size(), 65536, false)),
        value.size()
    );
    run(*queue, object->close(true));
    auto first = run(*queue, target->meta(*queue, 0));
    auto second = run(*queue, target->meta(*queue, 65536));
    EXPECT_EQ(first[2].config.sync_id, first[0].config.sync_id);
    EXPECT_EQ(second[2].config.sync_id, second[0].config.sync_id);
    EXPECT_NE(first[2].config.sync_id, second[2].config.sync_id);
}

TEST_F(WitnessTest, stale_clean_witness_cannot_orphan_first_degraded_write) {
    auto servers = std::make_unique<rawstor::tests::ObjectEnv>(29607, 29608);
    create("", "ost://127.0.0.1:29608");
    auto object = run(*queue, target->open(*queue, 0));
    servers.reset();
    {
        HiddenLocation offline_w(w);
        std::string value = "unsafe";
        EXPECT_THROW(
            run(*queue, object->pwrite(value.data(), value.size(), 0, false)),
            std::system_error
        );
        run(*queue, object->close(false));
    }
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    refused();
}

TEST_F(WitnessTest, listed_target_keeps_mds_witness_and_its_vote) {
    rawstor::tests::ObjectEnv servers(29609, 29610);
    create(servers.location());
    seed();
    rawstor::Location location(
        {rawstd::URI(a.uri()), rawstd::URI(b.uri()), rawstd::URI(witness)}
    );
    std::list<rawstor::Target> listed;
    RawstorPaginationToken token{};
    run(*queue, location.list(*queue, 1, listed, token));
    ASSERT_EQ(listed.size(), 1u);
    ASSERT_EQ(listed.front().uris().size(), 3u);
    EXPECT_EQ(listed.front().uris()[2].scheme(), "mds");
    HiddenLocation offline(b);
    auto object = run(*queue, listed.front().open(*queue, 0));
    write(*object);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, listing_keeps_data_and_witness_records_in_shared_store) {
    create();
    RawstdUUID data_id = new_id();
    rawstor::Target data({rawstd::URI(w.uri() + "/" + id_string(data_id))});
    RawstorObjectSpec data_spec{};
    data_spec.width = 1;
    data_spec.size = 65536;
    run(*queue, data.create(*queue, data_spec));
    rawstor::Location location({rawstd::URI(witness)});
    std::list<rawstor::Target> listed;
    RawstorPaginationToken token{};
    run(*queue, location.list(*queue, 0, listed, token));
    ASSERT_EQ(listed.size(), 2u);
    unsigned witnesses = 0, data_members = 0;
    for (const auto& entry : listed) {
        auto metadata = run(*queue, entry.meta(*queue, 0));
        ASSERT_EQ(metadata.size(), 1u);
        witnesses += metadata.front().member_role == RAWSTOR_MEMBER_WITNESS;
        data_members += metadata.front().member_role == RAWSTOR_MEMBER_DATA;
    }
    EXPECT_EQ(witnesses, 1u);
    EXPECT_EQ(data_members, 1u);
}

TEST_F(WitnessTest, explicit_lost_update_invalidates_witness_vote) {
    create();
    seed();
    auto config = metas()[2].config;
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(w.uri())));
    run(*queue, slot->set_config(id, 0, 2, config, RAWSTOR_CONFIG_STATE_LOST));
    run(*queue, slot->close());
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    HiddenLocation offline(b);
    refused();
}

TEST_F(WitnessTest, mds_explicit_lost_update_invalidates_witness_vote) {
    rawstor::tests::ObjectEnv servers(29611, 29612);
    create(servers.location());
    seed();
    auto config = metas()[2].config;
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(witness)));
    run(*queue, slot->set_config(id, 0, 2, config, RAWSTOR_CONFIG_STATE_LOST));
    run(*queue, slot->close());
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    HiddenLocation offline(b);
    refused();
}

TEST_F(WitnessTest, four_data_members_write_and_restart_on_half_plus_witness) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    seed();
    HiddenLocation offline_c(c), offline_d(d);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object, "newer");
    auto metadata = metas();
    ASSERT_EQ(metadata.size(), 5u);
    EXPECT_EQ(metadata[4].state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(metadata[4].config.sync_id, metadata[0].config.sync_id);
    EXPECT_EQ(metadata[4].config.sync_id, metadata[1].config.sync_id);
    EXPECT_EQ(metadata[4].config.roles[2], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    EXPECT_EQ(metadata[4].config.roles[3], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    EXPECT_EQ(metadata[4].config.roles[4], RAWSTOR_OBJECT_MEMBER_IN_SYNC);
    run(*queue, object->close(false));
    object = run(*queue, target->open(*queue, 0));
    std::string value(5, '\0');
    EXPECT_EQ(run(*queue, object->pread(value.data(), value.size(), 0)), 5u);
    EXPECT_EQ(value, "newer");
    write(*object, "again");
    run(*queue, object->close(true));
    object = run(*queue, target->open(*queue, 0));
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, four_data_members_require_two_matching_data_votes) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    seed();
    auto config = metas()[0].config;
    ++config.epoch;
    run(*queue, target->set_member_config(*queue, 0, 1, config, 0));
    HiddenLocation offline_c(c), offline_d(d);
    refused();
}

TEST_F(WitnessTest, four_data_members_reject_one_data_plus_witness) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    seed();
    HiddenLocation offline_b(b), offline_c(c), offline_d(d);
    refused();
}

TEST_F(WitnessTest, half_of_four_requires_durable_witness_before_write) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    seed();
    HiddenLocation offline_c(c), offline_d(d);
    auto object = run(*queue, target->open(*queue, 0));
    HiddenLocation offline_w(w);
    std::string value = "unsafe";
    EXPECT_THROW(
        run(*queue, object->pwrite(value.data(), value.size(), 0, false)),
        std::system_error
    );
    run(*queue, object->close(false));
}

TEST_F(WitnessTest, four_runtime_degrade_persists_witness_before_ack) {
    auto server_c = std::make_unique<rawstor::tests::ObjectEnv>(29613, 29614);
    auto server_d = std::make_unique<rawstor::tests::ObjectEnv>(29615, 29616);
    create_four("ost://127.0.0.1:29614", "ost://127.0.0.1:29616");
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    server_c.reset();
    server_d.reset();
    write(*object, "newer");
    auto metadata = metas();
    EXPECT_EQ(metadata[4].config.sync_id, metadata[0].config.sync_id);
    EXPECT_EQ(metadata[4].config.sync_id, metadata[1].config.sync_id);
    EXPECT_EQ(metadata[4].config.roles[2], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    EXPECT_EQ(metadata[4].config.roles[3], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    run(*queue, object->close(false));
    object = run(*queue, target->open(*queue, 0));
    std::string value(5, '\0');
    run(*queue, object->pread(value.data(), value.size(), 0));
    EXPECT_EQ(value, "newer");
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, four_runtime_degrade_freezes_without_witness) {
    auto server_c = std::make_unique<rawstor::tests::ObjectEnv>(29617, 29618);
    auto server_d = std::make_unique<rawstor::tests::ObjectEnv>(29619, 29620);
    create_four("ost://127.0.0.1:29618", "ost://127.0.0.1:29620");
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    server_c.reset();
    server_d.reset();
    HiddenLocation offline_w(w);
    std::string value = "unsafe";
    EXPECT_THROW(
        run(*queue, object->pwrite(value.data(), value.size(), 0, false)),
        std::system_error
    );
    EXPECT_THROW(run(*queue, object->close(false)), std::system_error);
}

TEST_F(WitnessTest, four_data_members_continue_on_three_without_witness) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    seed();
    HiddenLocation offline_d(d), offline_w(w);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object, "newer");
    auto metadata = metas();
    EXPECT_EQ(metadata[0].config.roles[4], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    EXPECT_EQ(metadata[1].config.sync_id, metadata[0].config.sync_id);
    EXPECT_EQ(metadata[2].config.sync_id, metadata[0].config.sync_id);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, six_data_members_write_on_three_plus_witness) {
    rawstor::tests::TmpDir c, d, e, f;
    witness = w.uri();
    spec.size = 65536;
    spec.width = 6;
    std::vector<rawstd::URI> members;
    for (const auto& uri :
         {a.uri(), b.uri(), c.uri(), d.uri(), e.uri(), f.uri(), witness}) {
        members.emplace_back(uri + "/" + id_string(id));
    }
    target = std::make_unique<rawstor::Target>(members);
    run(*queue, target->create(*queue, spec));
    seed();
    HiddenLocation offline_d(d), offline_e(e), offline_f(f);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object, "newer");
    EXPECT_EQ(metas()[6].config.sync_id, metas()[0].config.sync_id);
    run(*queue, object->close(false));
    object = run(*queue, target->open(*queue, 0));
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, rejects_witness_with_single_data_member) {
    spec.size = 65536;
    spec.width = 1;
    witness = w.uri();
    target = std::make_unique<rawstor::Target>(std::vector<rawstd::URI>{
        rawstd::URI(a.uri() + "/" + id_string(id)),
        rawstd::URI(witness + "/" + id_string(id))
    });
    EXPECT_THROW(run(*queue, target->create(*queue, spec)), std::system_error);
    EXPECT_THROW(run(*queue, target->open(*queue, 0)), std::system_error);
}

TEST_F(WitnessTest, metadata_failure_records_final_composition_before_ack) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    auto previous = metas()[0].config.sync_id;
    auto object = run(*queue, target->open(*queue, 0));
    HiddenLocation offline_d(d);
    write(*object, "newer");
    auto metadata = metas();
    EXPECT_NE(metadata[0].config.sync_id, previous);
    for (size_t index : {0u, 1u, 2u, 4u}) {
        EXPECT_EQ(metadata[index].config.sync_id, metadata[0].config.sync_id);
        EXPECT_EQ(
            metadata[index].config.roles[3], RAWSTOR_OBJECT_MEMBER_EXCLUDED
        );
        EXPECT_EQ(
            metadata[index].config.roles[4], RAWSTOR_OBJECT_MEMBER_IN_SYNC
        );
    }
    run(*queue, object->close(false));
}

TEST_F(WitnessTest, writer_queues_share_witness_until_last_clean_close) {
    create();
    auto second_queue = rawio::Queue::create(128);
    auto first = run(*queue, target->open(*queue, 0));
    auto second = run(*second_queue, target->open(*second_queue, 0));
    write(*first);
    run(*queue, first->close(true));
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    std::string value = "newer";
    EXPECT_EQ(
        run(*second_queue,
            second->pwrite(value.data(), value.size(), 0, false)),
        value.size()
    );
    run(*second_queue, second->close(true));
    EXPECT_EQ(metas()[2].state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    HiddenLocation offline_b(b);
    auto reopened = run(*queue, target->open(*queue, 0));
    std::string actual(value.size(), '\0');
    run(*queue, reopened->pread(actual.data(), actual.size(), 0));
    EXPECT_EQ(actual, value);
    run(*queue, reopened->close(true));
}

TEST_F(WitnessTest, concurrent_writer_queues_share_half_plus_witness) {
    rawstor::tests::TmpDir c, d;
    create_four(c.uri(), d.uri());
    HiddenLocation offline_c(c), offline_d(d);
    constexpr size_t writers = 3;
    std::barrier opened(static_cast<std::ptrdiff_t>(writers));
    std::atomic<unsigned> failures{0};
    std::vector<std::thread> threads;
    for (size_t index = 0; index < writers; ++index) {
        threads.emplace_back([&, index]() {
            bool arrived = false;
            try {
                auto writer_queue = rawio::Queue::create(128);
                auto object =
                    run(*writer_queue, target->open(*writer_queue, 0));
                opened.arrive_and_wait();
                arrived = true;
                std::string value = "writer-" + std::to_string(index);
                for (unsigned repeat = 0; repeat < 8; ++repeat) {
                    auto written =
                        run(*writer_queue,
                            object->pwrite(
                                value.data(), value.size(), index * 4096, false
                            ));
                    if (written != value.size()) {
                        ++failures;
                    }
                }
                run(*writer_queue, object->close(true));
            } catch (const std::exception& error) {
                if (!arrived) {
                    opened.arrive_and_drop();
                }
                ++failures;
                ADD_FAILURE() << error.what();
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    ASSERT_EQ(failures.load(), 0u);
    auto metadata = metas();
    EXPECT_EQ(metadata[4].state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(metadata[4].config.sync_id, metadata[0].config.sync_id);
    EXPECT_EQ(metadata[4].config.sync_id, metadata[1].config.sync_id);
    auto object = run(*queue, target->open(*queue, 0));
    for (size_t index = 0; index < writers; ++index) {
        std::string expected = "writer-" + std::to_string(index);
        std::string actual(expected.size(), '\0');
        run(*queue, object->pread(actual.data(), actual.size(), index * 4096));
        EXPECT_EQ(actual, expected);
    }
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, native_witness_update_preserves_register_ballots) {
    create();
    auto config = metas()[2].config;
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(witness)));
    RawstorObjectBallot ballot{1, 42}, next{2, 42};
    auto prepared = run(*queue, slot->sync_prepare(id, 0, ballot));
    ASSERT_TRUE(prepared.ok);
    auto accepted =
        run(*queue, slot->sync_accept(id, 0, 2, ballot, next, config));
    ASSERT_TRUE(accepted.ok);
    run(*queue, slot->set_config(id, 0, 2, config, RAWSTOR_CONFIG_STATE_DIRTY));
    run(*queue, slot->close());
    auto metadata = metas()[2];
    EXPECT_EQ(metadata.accepted.counter, ballot.counter);
    EXPECT_EQ(metadata.accepted.proposer, ballot.proposer);
    EXPECT_EQ(metadata.promised.counter, next.counter);
    EXPECT_EQ(metadata.promised.proposer, next.proposer);
}

TEST_F(WitnessTest, missing_witness_type_is_recovered_from_surviving_metadata) {
    create();
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(witness)));
    run(*queue, slot->remove(id, 0));
    run(*queue, slot->close());
    auto metadata = metas();
    EXPECT_EQ(metadata[2].state, RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE);
    EXPECT_EQ(metadata[2].member_role, RAWSTOR_MEMBER_WITNESS);
    auto object = run(*queue, target->open(*queue, 0));
    write(*object);
    metadata = metas();
    EXPECT_EQ(metadata[2].member_role, RAWSTOR_MEMBER_WITNESS);
    EXPECT_EQ(metadata[2].spec.size, 0u);
    run(*queue, object->close(true));
}

TEST_F(WitnessTest, mds_lists_objects_and_witnesses_with_one_cursor) {
    rawstor::tests::ObjectEnv servers(29623, 29624);
    create(servers.location());
    RawstdUUID object_id = new_id();
    rawstor::Target data(
        {rawstd::URI(servers.location() + "/" + id_string(object_id))}
    );
    RawstorObjectSpec data_spec{};
    data_spec.size = 65536;
    data_spec.chunk_size = 65536;
    data_spec.width = 1;
    run(*queue, data.create(*queue, data_spec));
    rawstor::Location location({rawstd::URI(servers.location())});
    RawstorPaginationToken token{};
    unsigned witnesses = 0, objects = 0;
    for (unsigned page = 0; page < 4; ++page) {
        std::list<rawstor::Target> listed;
        run(*queue, location.list(*queue, 1, listed, token));
        if (listed.empty()) {
            break;
        }
        ASSERT_EQ(listed.size(), 1u);
        auto metadata = run(*queue, listed.front().meta(*queue, 0));
        ASSERT_EQ(metadata.size(), 1u);
        witnesses += metadata.front().member_role == RAWSTOR_MEMBER_WITNESS;
        objects += metadata.front().member_role == RAWSTOR_MEMBER_DATA;
        if (rawstor_pagination_token_empty(&token)) {
            break;
        }
    }
    EXPECT_EQ(witnesses, 1u);
    EXPECT_EQ(objects, 1u);
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));
}

TEST_F(WitnessTest, plain_mds_witness_listing_preserves_all_chunk_offsets) {
    rawstor::tests::ObjectEnv servers(29625, 29626);
    witness = servers.location();
    spec.size = 131072;
    spec.chunk_size = 65536;
    spec.width = 2;
    rawstor::Location location(
        {rawstd::URI(a.uri()), rawstd::URI(b.uri()), rawstd::URI(witness)}
    );
    target = std::make_unique<rawstor::Target>(
        run(*queue, location.create(*queue, id, spec))
    );
    rawstor::Location witness_location({rawstd::URI(witness)});
    std::list<rawstor::Target> witness_records;
    RawstorPaginationToken witness_token{};
    run(*queue,
        witness_location.list(*queue, 1, witness_records, witness_token));
    ASSERT_EQ(witness_records.size(), 1u);
    ASSERT_EQ(witness_records.front().uris().size(), 2u);
    EXPECT_EQ(run(*queue, witness_records.front().spec(*queue)).size, 0u);
    std::list<rawstor::Target> listed;
    RawstorPaginationToken token{};
    run(*queue, location.list(*queue, 1, listed, token));
    ASSERT_EQ(listed.size(), 1u);
    ASSERT_EQ(listed.front().uris().size(), 6u);
    HiddenLocation offline_b(b);
    auto object = run(*queue, listed.front().open(*queue, 0));
    std::string value = "last chunk";
    EXPECT_EQ(
        run(*queue, object->pwrite(value.data(), value.size(), 65536, false)),
        value.size()
    );
    run(*queue, object->close(true));
}
