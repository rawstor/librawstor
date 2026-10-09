#include "object.hpp"
#include "object_env.hpp"
#include "opts.h"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

/*
 * A copy keeps its own DIRTY/CLEAN/LOST from the sessions writing it
 * (docs/mirroring.md, "DIRTY, CLEAN and LOST"): a file:// copy opened
 * directly is its own member, in this process.
 */

namespace {

template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

void run(rawio::Queue& q, rawstd::Task<void> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    t.get();
}

RawstdUUID new_id() {
    RawstdUUID id;
    if (rawstd_uuid7_init(&id) != 0) {
        throw std::runtime_error("rawstd_uuid7_init() failed");
    }
    return id;
}

std::string id_string(const RawstdUUID& id) {
    RawstdUUIDString s;
    rawstd_uuid_to_string(&id, &s);
    return s;
}

class FileObject {
private:
    rawstor::tests::TmpDir _dir;
    RawstdUUID _id;

public:
    rawstor::Target target;

    FileObject() :
        _id(new_id()),
        target({rawstd::URI(rawstd::URI(_dir.uri()), id_string(_id))}) {}

    void create(rawio::Queue& queue) {
        RawstorObjectSpec spec{
            .size = 1u << 20,
            .width = 1,
            .chunk_size = 0,
            .stripe_width = 0,
            .failure_domain = 0,
        };
        run(queue, target.create(queue, spec));
    }

    RawstorObjectMeta meta(rawio::Queue& queue) {
        return run(queue, target.meta(queue, 0)).front();
    }
};

void write_one(rawio::Queue& queue, rawstor::Object& object) {
    std::string data = "ping";
    run(queue, object.pwrite(data.data(), data.size(), 0, false));
}

} // namespace

TEST(MemberStateTest, first_write_dirties_and_clean_close_cleans) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    FileObject f;
    f.create(*queue);

    std::unique_ptr<rawstor::Object> object =
        run(*queue, f.target.open(*queue, 0));
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(f.meta(*queue).writers, 1u);

    write_one(*queue, *object);
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);

    run(*queue, object->close());
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(f.meta(*queue).writers, 0u);
}

TEST(MemberStateTest, last_clean_departure_cleans) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    FileObject f;
    f.create(*queue);

    std::unique_ptr<rawstor::Object> a = run(*queue, f.target.open(*queue, 0));
    std::unique_ptr<rawstor::Object> b = run(*queue, f.target.open(*queue, 0));
    EXPECT_EQ(f.meta(*queue).writers, 2u);

    write_one(*queue, *a);
    run(*queue, a->close());
    // b still has it open: the copy stays DIRTY.
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(f.meta(*queue).writers, 1u);

    run(*queue, b->close());
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MemberStateTest, abandoned_writer_loses_the_copy) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    FileObject f;
    f.create(*queue);

    std::unique_ptr<rawstor::Object> a = run(*queue, f.target.open(*queue, 0));
    std::unique_ptr<rawstor::Object> b = run(*queue, f.target.open(*queue, 0));
    write_one(*queue, *a);
    run(*queue, a->close(false));
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_LOST);

    // A later clean departure does not hide it, and neither does a new
    // configuration.
    write_one(*queue, *b);
    RawstorObjectConfig config = f.meta(*queue).config;
    config.epoch += 1;
    run(*queue, f.target.set_member_config(*queue, 0, 0, config, 0));
    run(*queue, b->close());
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_LOST);

    // Only an explicit clear does.
    run(*queue, f.target.set_member_config(
                    *queue, 0, 0, config, RAWSTOR_CONFIG_CLEAR_LOST
                ));
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MemberStateTest, abandoned_reader_changes_nothing) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    FileObject f;
    f.create(*queue);

    // Open for writing, but nothing written: leaving uncleanly loses
    // nothing.
    std::unique_ptr<rawstor::Object> a = run(*queue, f.target.open(*queue, 0));
    run(*queue, a->close(false));
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MemberStateTest, set_config_keeps_the_state_and_records_roles) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    FileObject f;
    f.create(*queue);

    std::unique_ptr<rawstor::Object> a = run(*queue, f.target.open(*queue, 0));
    write_one(*queue, *a);

    RawstorObjectConfig config{};
    config.epoch = 4;
    config.sync_id = 0x44;
    config.nroles = 2;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    config.roles[1] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    run(*queue, f.target.set_member_config(*queue, 0, 0, config, 0));

    RawstorObjectMeta meta = f.meta(*queue);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.config.epoch, 4u);
    EXPECT_EQ(meta.config.sync_id, 0x44u);
    ASSERT_EQ(meta.config.nroles, 2);
    EXPECT_EQ(meta.config.roles[1], RAWSTOR_OBJECT_MEMBER_EXCLUDED);

    run(*queue, a->close());
}

// An mds:// object passes its writer's departure on to the chunks it
// opens: a clean close leaves their copies CLEAN, an abandoned one LOST.
// The OST marks a dropped session's copy as it notices the drop, on its
// own thread, so the state is waited for.
TEST(MemberStateTest, mds_object_passes_departure_to_its_chunks) {
    rawstor::tests::ObjectEnv env(8830, 8831);
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    rawstor::Target target(
        {rawstd::URI(rawstd::URI(env.location()), id_string(new_id()))}
    );
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 1u << 20,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, target.create(*queue, spec));

    auto wait_state = [&](RawstorObjectSyncStateValue state) {
        RawstorObjectSyncStateValue seen = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
        for (int i = 0; i < 500; ++i) {
            seen = run(*queue, target.meta(*queue, 0)).front().state;
            if (seen == state) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return seen;
    };

    std::unique_ptr<rawstor::Object> a = run(*queue, target.open(*queue, 0));
    write_one(*queue, *a);
    EXPECT_EQ(
        wait_state(RAWSTOR_OBJECT_SYNC_STATE_DIRTY),
        RAWSTOR_OBJECT_SYNC_STATE_DIRTY
    );
    run(*queue, a->close());
    EXPECT_EQ(
        wait_state(RAWSTOR_OBJECT_SYNC_STATE_CLEAN),
        RAWSTOR_OBJECT_SYNC_STATE_CLEAN
    );

    std::unique_ptr<rawstor::Object> b = run(*queue, target.open(*queue, 0));
    write_one(*queue, *b);
    run(*queue, b->close(false));
    EXPECT_EQ(
        wait_state(RAWSTOR_OBJECT_SYNC_STATE_LOST),
        RAWSTOR_OBJECT_SYNC_STATE_LOST
    );
}

// A writer that dropped its session may be deciding alone on the other
// member of two: a LOST copy refuses to decide alone (docs/multiattach.md,
// "N = 2").
TEST(MemberStateTest, lost_copy_refuses_to_decide_alone) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    FileObject f;
    f.create(*queue);

    std::unique_ptr<rawstor::Object> a = run(*queue, f.target.open(*queue, 0));
    write_one(*queue, *a);
    run(*queue, a->close(false));
    ASSERT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_LOST);

    RawstorObjectConfig config = f.meta(*queue).config;
    config.epoch += 1;
    try {
        run(*queue,
            f.target.sync_accept(
                *queue, 0, 0, {1, 0x77}, {}, config, RAWSTOR_SYNC_ALONE, 0
            ));
        FAIL() << "accepted alone on a LOST copy";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EBUSY);
    }

    rawstor::Backend::SyncReply reply =
        run(*queue,
            f.target.sync_accept(*queue, 0, 0, {1, 0x77}, {}, config, 0, 0));
    EXPECT_TRUE(reply.ok);
}
