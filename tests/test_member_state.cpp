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

#include <array>
#include <barrier>
#include <chrono>
#include <exception>
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

class MemberObject {
private:
    rawstor::tests::TmpDir _dir;
    RawstdUUID _id;

public:
    rawstor::Target target;

    MemberObject() :
        _id(new_id()),
        target({rawstd::URI(rawstd::URI(_dir.uri()), id_string(_id))}) {}

    explicit MemberObject(const rawstd::URI& location) :
        _id(new_id()),
        target({rawstd::URI(location, id_string(_id))}) {}

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
    MemberObject f;
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
    MemberObject f;
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
    MemberObject f;
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
    MemberObject f;
    f.create(*queue);

    // Open for writing, but nothing written: leaving uncleanly loses
    // nothing.
    std::unique_ptr<rawstor::Object> a = run(*queue, f.target.open(*queue, 0));
    run(*queue, a->close(false));
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MemberStateTest, set_config_keeps_the_state_and_records_roles) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    MemberObject f;
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

// Each writer has its own thread and Queue; metadata uses a third Slot.
// Phase barriers let us inspect completed operations without timing probes.
namespace {

void expect_thread_shared_copy_state(MemberObject& f) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    f.create(*queue);
    std::barrier phase(3);
    std::array<std::exception_ptr, 2> errors{};
    std::array<std::thread, 2> writers;
    for (size_t i = 0; i < writers.size(); ++i) {
        writers[i] = std::thread([&, i]() {
            std::unique_ptr<rawio::Queue> worker_queue;
            std::unique_ptr<rawstor::Object> object;
            for (unsigned int step = 0; step < 4; ++step) {
                phase.arrive_and_wait();
                if (!errors[i]) {
                    try {
                        if (step == 0) {
                            worker_queue = rawio::Queue::create(64);
                            object =
                                run(*worker_queue,
                                    f.target.open(*worker_queue, 0));
                        } else if (step == 1) {
                            std::string data(4096, static_cast<char>('A' + i));
                            run(*worker_queue, object->pwrite(
                                                   data.data(), data.size(),
                                                   i * data.size(), false
                                               ));
                        } else if (step == i + 2) {
                            run(*worker_queue, object->close());
                        }
                    } catch (...) {
                        errors[i] = std::current_exception();
                    }
                }
                phase.arrive_and_wait();
            }
        });
    }
    for (unsigned int step = 0; step < 4; ++step) {
        phase.arrive_and_wait();
        if (step == 1) {
            // Metadata-only access competes with both first DIRTY marks.
            RawstorObjectConfig config{};
            config.epoch = 4;
            config.sync_id = 0x44;
            config.nroles = 1;
            config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
            EXPECT_NO_THROW(
                run(*queue, f.target.set_member_config(*queue, 0, 0, config, 0))
            );
        }
        phase.arrive_and_wait();
        EXPECT_NO_THROW({
            RawstorObjectMeta meta = f.meta(*queue);
            // A remote close completes before the server retires its session.
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(5);
            const uint32_t expected_writers =
                step < 2 ? 2u : (step == 2 ? 1u : 0u);
            while (meta.writers != expected_writers &&
                   std::chrono::steady_clock::now() < deadline) {
                meta = f.meta(*queue);
            }
            EXPECT_EQ(meta.writers, step < 2 ? 2u : (step == 2 ? 1u : 0u));
            EXPECT_EQ(
                meta.state, step == 0 || step == 3
                                ? RAWSTOR_OBJECT_SYNC_STATE_CLEAN
                                : RAWSTOR_OBJECT_SYNC_STATE_DIRTY
            );
            if (step > 0) {
                EXPECT_EQ(meta.config.epoch, 4u);
                EXPECT_EQ(meta.config.sync_id, 0x44u);
            }
        });
    }
    for (std::thread& writer : writers) {
        writer.join();
    }
    for (const auto& error : errors) {
        if (error) {
            EXPECT_NO_THROW(std::rethrow_exception(error));
        }
    }
    std::unique_ptr<rawstor::Object> reader =
        run(*queue, f.target.open(*queue, RAWSTOR_READONLY));
    std::string actual(8192, '\0');
    EXPECT_EQ(
        run(*queue, reader->pread(actual.data(), actual.size(), 0)),
        actual.size()
    );
    EXPECT_EQ(actual, std::string(4096, 'A') + std::string(4096, 'B'));
    run(*queue, reader->close());
}

} // namespace

TEST(MemberStateTest, threads_share_copy_state_and_metadata_transitions) {
    MemberObject f;
    expect_thread_shared_copy_state(f);
}

TEST(MemberStateTest, ost_threads_share_copy_state_and_metadata_transitions) {
    rawstor::tests::ObjectEnv env(8788, 8789);
    MemberObject f(rawstd::URI("ost://127.0.0.1:8789"));
    expect_thread_shared_copy_state(f);
}
