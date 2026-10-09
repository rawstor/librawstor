#include "object.hpp"
#include "opts.h"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>
#include <string>

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
