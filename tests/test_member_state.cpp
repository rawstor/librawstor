#include "backend.hpp"
#include "object.hpp"
#include "object_env.hpp"
#include "opts.h"
#include "slot.hpp"
#include "target.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <array>
#include <barrier>
#include <chrono>
#include <exception>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>

#include <cerrno>

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
        return run(queue, target.meta(queue)).front();
    }
};

void write_one(rawio::Queue& queue, rawstor::Object& object) {
    std::string data = "ping";
    run(queue, object.pwrite(data.data(), data.size(), 0, false));
}

} // namespace

TEST(MemberStateTest, unreachable_metadata_cannot_be_opened_for_io) {
    auto queue = rawio::Queue::create(64);
    rawstor::tests::TmpDir dir;
    const auto id = new_id();
    const rawstd::URI location(dir.uri());
    auto slot = run(*queue, rawstor::Slot::create(*queue, location));
    RawstorObjectSpec spec{};
    spec.size = 4096;
    spec.width = 1;
    run(*queue, slot->create(id, 0, spec, RAWSTOR_MEMBER_DATA));
    auto backend = run(*queue, rawstor::Backend::create(*queue, location));
    run(*queue, backend->set_state(
                    id, 0, RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
                    RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE
                ));
    run(*queue, backend->close());
    EXPECT_EQ(
        run(*queue, slot->meta(id, 0)).front().state,
        RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE
    );
    try {
        run(*queue, slot->open({}, id, 0, 0, RawstdUUID{}));
        FAIL() << "Unreachable member opened for I/O";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ENOTCONN);
    }
    run(*queue, slot->close());
}

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
    run(*queue, f.target.set_member_config(*queue, 0, config, 0));
    run(*queue, b->close());
    EXPECT_EQ(f.meta(*queue).state, RAWSTOR_OBJECT_SYNC_STATE_LOST);

    // Only an explicit clear does.
    run(*queue, f.target.set_member_config(
                    *queue, 0, config, RAWSTOR_CONFIG_CLEAR_LOST
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
    run(*queue, f.target.set_member_config(*queue, 0, config, 0));

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
            seen = run(*queue,
                       run(*queue, target.chunks(*queue)).front().meta(*queue))
                       .front()
                       .state;
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

void expect_clear_lost_with_writer(MemberObject& f) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(64);
    f.create(*queue);
    auto first = run(*queue, f.target.open(*queue, 0));
    auto second = run(*queue, f.target.open(*queue, 0));
    write_one(*queue, *first);
    run(*queue, first->close(false));
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    RawstorObjectMeta meta = f.meta(*queue);
    while (meta.state != RAWSTOR_OBJECT_SYNC_STATE_LOST &&
           std::chrono::steady_clock::now() < deadline) {
        meta = f.meta(*queue);
    }
    ASSERT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    ASSERT_EQ(meta.writers, 1u);
    RawstorObjectConfig config = meta.config;
    ++config.epoch;
    run(*queue, f.target.set_member_config(
                    *queue, 0, config, RAWSTOR_CONFIG_CLEAR_LOST
                ));
    meta = f.meta(*queue);
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    EXPECT_EQ(meta.writers, 1u);
    EXPECT_EQ(meta.config.epoch, config.epoch);
    write_one(*queue, *second);
    run(*queue, second->close());
}

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
                run(*queue, f.target.set_member_config(*queue, 0, config, 0))
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

namespace {

void expect_copy_write_requests(const rawstd::URI& location) {
    auto queue = rawio::Queue::create(16);
    RawstdUUID id;
    ASSERT_EQ(rawstd_uuid7_init(&id), 0);
    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);
    rawstor::Target target({rawstd::URI(location, id_string)});
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, target.create(*queue, spec));
    auto writer = run(*queue, rawstor::Slot::create(*queue, location));
    auto peer = run(*queue, rawstor::Slot::create(*queue, location));
    run(*queue, writer->open({}, id, 0, 0, RawstdUUID{}));
    run(*queue, peer->open({}, id, 0, 0, RawstdUUID{}));

    auto expect_stale = [&](rawstd::Task<size_t> task) {
        try {
            run(*queue, std::move(task));
            ADD_FAILURE() << "stale request accepted";
        } catch (const std::system_error& e) {
            EXPECT_EQ(e.code().value(), ESTALE);
        }
    };
    RawstorObjectConfig config{};
    config.epoch = 5;
    config.nroles = 1;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    run(*queue, peer->set_config(id, 0, 0, config, 0));
    std::string client_data(512, 'W');
    expect_stale(
        writer->pwrite(client_data.data(), client_data.size(), 512, false, 4)
    );
    iovec stale_iov{client_data.data(), client_data.size()};
    expect_stale(
        writer->pwritev(&stale_iov, 1, client_data.size(), 512, false, 4)
    );
    expect_stale(writer->discard(512, 0, 4));
    expect_stale(writer->write_zeroes(512, 0, false, false, 4));
    try {
        run(*queue, writer->flush(4));
        ADD_FAILURE() << "stale flush accepted";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), ESTALE);
    }
    // RESYNC needs a copy currently tracking client writes.
    expect_stale(writer->resync_pwrite(
        client_data.data(), client_data.size(), 0, false, 5
    ));

    config.epoch = 7;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    run(*queue, peer->set_config(id, 0, 0, config, 0));
    ASSERT_EQ(
        run(*queue, writer->pwrite(
                        client_data.data(), client_data.size(), 512, false, 7
                    )),
        client_data.size()
    );
    // Protect only the bytes written, including partial sectors.
    ASSERT_EQ(
        run(*queue, writer->pwrite(client_data.data(), 10, 1636, false, 7)), 10u
    );
    std::string prefix(12, 'P');
    ASSERT_EQ(
        run(*queue,
            writer->pwrite(prefix.data(), prefix.size(), 1628, false, 7)),
        prefix.size()
    );
    std::string left = "abc";
    std::string right = "xyz";
    iovec parts[] = {{left.data(), left.size()}, {right.data(), right.size()}};
    ASSERT_EQ(run(*queue, writer->pwritev(parts, 2, 6, 1533, false, 7)), 6u);
    std::string repair(2048, 'R');
    ASSERT_EQ(
        run(*queue,
            peer->resync_pwrite(repair.data(), repair.size(), 0, false, 7)),
        repair.size()
    );
    std::string data(2048, '\0');
    ASSERT_EQ(
        run(*queue, writer->pread(data.data(), data.size(), 0)), data.size()
    );
    std::string expected(2048, 'R');
    expected.replace(512, client_data.size(), client_data);
    expected.replace(1636, 10, client_data.data(), 10);
    expected.replace(1628, prefix.size(), prefix);
    expected.replace(1533, 6, left + right);
    EXPECT_EQ(data, expected);
    ASSERT_EQ(
        run(*queue, peer->resync_write_zeroes(data.size(), 0, false, false, 7)),
        data.size()
    );
    ASSERT_EQ(
        run(*queue, writer->pread(data.data(), data.size(), 0)), data.size()
    );
    expected.assign(2048, '\0');
    expected.replace(512, client_data.size(), client_data);
    expected.replace(1636, 10, client_data.data(), 10);
    expected.replace(1628, prefix.size(), prefix);
    expected.replace(1533, 6, left + right);
    EXPECT_EQ(data, expected);

    // Raising the configuration on another open preserves admitted data.
    std::string block(4096, 'A');
    auto written = writer->pwrite(block.data(), block.size(), 4096, false, 7);
    bool remote = location.scheme() == "ost";
    if (remote) {
        // A second connection may deliver SET_CONFIG before the first
        // connection has delivered this write. Await its acknowledgement.
        EXPECT_EQ(run(*queue, std::move(written)), block.size());
    }
    config.epoch = 9;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    run(*queue, peer->set_config(id, 0, 0, config, 0));
    std::string actual(block.size(), '\0');
    ASSERT_EQ(
        run(*queue, peer->pread(actual.data(), actual.size(), 4096)),
        actual.size()
    );
    EXPECT_EQ(actual, block);
    if (!remote) {
        EXPECT_EQ(run(*queue, std::move(written)), block.size());
    }
    expect_stale(
        writer->pwrite(client_data.data(), client_data.size(), 0, false, 7)
    );
    expect_stale(
        peer->resync_pwrite(repair.data(), repair.size(), 0, false, 9)
    );
    EXPECT_EQ(
        run(*queue, writer->pwrite(
                        client_data.data(), client_data.size(), 0, false, 0
                    )),
        client_data.size()
    );
    run(*queue, writer->flush(9));
    run(*queue, peer->flush(9));
    run(*queue, writer->leave());
    run(*queue, peer->leave());
    run(*queue, writer->close());
    run(*queue, peer->close());
    auto meta =
        run(*queue, run(*queue, target.chunks(*queue)).front().meta(*queue))
            .front();
    EXPECT_EQ(meta.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(meta.writers, 0u);
}

} // namespace

TEST(MemberStateTest, shared_copy_fences_and_preserves_client_sectors) {
    rawstor::tests::TmpDir dir;
    expect_copy_write_requests(rawstd::URI(dir.uri()));
}

TEST(MemberStateTest, ost_forwards_copy_write_requests_to_slot) {
    rawstor::tests::ObjectEnv env(8796, 8797);
    expect_copy_write_requests(rawstd::URI("ost://127.0.0.1:8797"));
}

TEST(MemberStateTest, clear_lost_keeps_an_open_writer_dirty) {
    MemberObject f;
    expect_clear_lost_with_writer(f);
}

TEST(MemberStateTest, ost_clear_lost_keeps_an_open_writer_dirty) {
    rawstor::tests::ObjectEnv env(8786, 8787);
    MemberObject f(rawstd::URI("ost://127.0.0.1:8787"));
    expect_clear_lost_with_writer(f);
}

TEST(
    MemberStateTest,
    resync_tracking_bounds_fragmentation_and_reuses_merged_ranges
) {
    rawstor::tests::TmpDir dir;
    auto queue = rawio::Queue::create(16);
    RawstdUUID id = new_id();
    rawstd::URI location(dir.uri());
    rawstor::Target target({rawstd::URI(location, id_string(id))});
    RawstorObjectSpec spec{
        .size = 1u << 20,
        .width = 1,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    run(*queue, target.create(*queue, spec));
    auto slot = run(*queue, rawstor::Slot::create(*queue, location));
    run(*queue, slot->open({}, id, 0, 0, RawstdUUID{}));
    RawstorObjectConfig config{};
    config.epoch = 1;
    config.nroles = 1;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    run(*queue, slot->set_config(id, 0, 0, config, 0));
    char data = 'B';
    size_t count = 0;
    bool limited = false;
    for (; count < 250000; ++count) {
        try {
            run(*queue, slot->pwrite(&data, 1, 2 * count, false, 1));
        } catch (const std::system_error& e) {
            EXPECT_EQ(e.code().value(), ENOBUFS);
            limited = true;
            break;
        }
    }
    EXPECT_TRUE(limited);
    EXPECT_GT(count, 1u);
    // Updating an existing range needs no extra capacity; bridging two
    // ranges frees capacity for a new, disjoint write.
    EXPECT_EQ(run(*queue, slot->pwrite(&data, 1, 0, false, 1)), 1u);
    EXPECT_EQ(run(*queue, slot->pwrite(&data, 1, 1, false, 1)), 1u);
    EXPECT_EQ(run(*queue, slot->pwrite(&data, 1, 2 * count, false, 1)), 1u);
    std::string repair(4, 'R');
    EXPECT_EQ(
        run(*queue,
            slot->resync_pwrite(repair.data(), repair.size(), 0, false, 1)),
        repair.size()
    );
    std::string actual(4, '\0');
    EXPECT_EQ(
        run(*queue, slot->pread(actual.data(), actual.size(), 0)), actual.size()
    );
    EXPECT_EQ(actual, "BBBR");
    run(*queue, slot->leave());
    run(*queue, slot->close());
}

TEST(ProtocolTest, metadata_round_trip_preserves_members_and_register) {
    for (auto role : {RAWSTOR_MEMBER_DATA, RAWSTOR_MEMBER_WITNESS}) {
        RawstorObjectMeta input{};
        input.spec = {
            .size = UINT64_C(1) << 63,
            .width = 254,
            .chunk_size = UINT64_C(1) << 63,
            .stripe_width = 0,
            .failure_domain = 0
        };
        input.member_role = role;
        input.state = RAWSTOR_OBJECT_SYNC_STATE_LOST;
        input.writers = 3;
        input.config.epoch = 23;
        input.config.sync_id = 42;
        input.config.sync_id_history[3] = 19;
        input.config.resync_owner = 11;
        input.config.nroles = 255;
        input.config.roles[254] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
        input.promised = {5, 7};
        input.accepted = {3, 9};
        RawstorFrameMetaPayload wire{};
        ASSERT_EQ(rawstor_frame_meta_encode(&wire, &input), 0);
        RawstorObjectMeta output{};
        ASSERT_EQ(rawstor_frame_meta_decode(&wire, &output), 0);
        EXPECT_EQ(output.spec.size, input.spec.size);
        EXPECT_EQ(output.spec.width, input.spec.width);
        EXPECT_EQ(output.spec.chunk_size, input.spec.chunk_size);
        EXPECT_EQ(output.member_role, role);
        EXPECT_EQ(output.state, input.state);
        EXPECT_EQ(output.writers, input.writers);
        EXPECT_EQ(output.config.epoch, input.config.epoch);
        EXPECT_EQ(output.config.sync_id, input.config.sync_id);
        EXPECT_EQ(output.config.sync_id_history[3], 19u);
        EXPECT_EQ(output.config.resync_owner, 11u);
        EXPECT_EQ(output.config.nroles, 255);
        EXPECT_EQ(output.config.roles[254], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
        EXPECT_EQ(output.promised.counter, 5u);
        EXPECT_EQ(output.promised.proposer, 7u);
        EXPECT_EQ(output.accepted.counter, 3u);
        EXPECT_EQ(output.accepted.proposer, 9u);
    }
}

TEST(ProtocolTest, conversion_rejects_unrepresentable_metadata) {
    RawstorObjectMeta meta{};
    meta.member_role = RAWSTOR_MEMBER_DATA;
    meta.spec.width = 256;
    RawstorFrameMetaPayload wire{};
    EXPECT_EQ(rawstor_frame_meta_encode(&wire, &meta), EINVAL);
    meta.spec.width = 2;
    meta.spec.chunk_size = 3;
    EXPECT_EQ(rawstor_frame_meta_encode(&wire, &meta), EINVAL);
    meta.spec.chunk_size = 4096;
    ASSERT_EQ(rawstor_frame_meta_encode(&wire, &meta), 0);
    wire.chunk_shift = 64;
    EXPECT_EQ(rawstor_frame_meta_decode(&wire, &meta), EPROTO);
    wire.chunk_shift = 12;
    wire.member_role = 0;
    EXPECT_EQ(rawstor_frame_meta_decode(&wire, &meta), EPROTO);
    wire.member_role = RAWSTOR_MEMBER_DATA;
    wire.config.nroles = 1;
    wire.config.roles[0] = RAWSTOR_OBJECT_MEMBER_EXCLUDED + 1;
    EXPECT_EQ(rawstor_frame_meta_decode(&wire, &meta), EINVAL);
}

TEST(ProtocolTest, config_encoding_clears_unused_roles) {
    RawstorObjectConfig config{};
    config.nroles = 1;
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    RawstorFrameConfig wire;
    memset(&wire, 0xff, sizeof(wire));
    ASSERT_EQ(rawstor_frame_config_encode(&wire, &config), 0);
    EXPECT_EQ(wire.roles[0], RAWSTOR_OBJECT_MEMBER_IN_SYNC);
    EXPECT_EQ(wire.roles[1], 0);
    EXPECT_EQ(wire.roles[254], 0);
    config.roles[0] = RAWSTOR_OBJECT_MEMBER_EXCLUDED + 1;
    EXPECT_EQ(rawstor_frame_config_encode(&wire, &config), EINVAL);
}

TEST(ProtocolTest, allocation_preserves_identity_and_placement) {
    RawstorObjectSpec input{
        .size = 16384,
        .width = 2,
        .chunk_size = 4096,
        .stripe_width = 3,
        .failure_domain = RAWSTOR_OBJ_DOMAIN_SERVER
    };
    RawstorFrameAllocatePayload wire{};
    wire.object_id[0] = 17;
    wire.chunk_offset = 4096;
    ASSERT_EQ(
        rawstor_frame_allocate_encode(&wire, &input, RAWSTOR_MEMBER_WITNESS), 0
    );
    EXPECT_EQ(wire.object_id[0], 17);
    EXPECT_EQ(wire.chunk_offset, 4096u);
    RawstorObjectSpec output{};
    RawstorMemberRole role{};
    ASSERT_EQ(rawstor_frame_allocate_decode(&wire, &output, &role), 0);
    EXPECT_EQ(output.size, input.size);
    EXPECT_EQ(output.width, input.width);
    EXPECT_EQ(output.chunk_size, input.chunk_size);
    EXPECT_EQ(output.stripe_width, input.stripe_width);
    EXPECT_EQ(output.failure_domain, input.failure_domain);
    EXPECT_EQ(role, RAWSTOR_MEMBER_WITNESS);
}

TEST(ProtocolTest, rejects_unknown_sync_states_but_preserves_unreachable) {
    RawstorFrameMetaPayload wire{};
    wire.member_role = RAWSTOR_MEMBER_DATA;
    wire.width = 1;
    RawstorObjectMeta meta{};
    for (unsigned int state = 0; state <= UINT8_MAX; ++state) {
        wire.state = static_cast<RawstorSyncStateType>(state);
        int result = rawstor_frame_meta_decode(&wire, &meta);
        EXPECT_EQ(result, state <= RAWSTOR_OBJECT_SYNC_STATE_LOST ? 0 : EPROTO);
        if (result == 0) {
            EXPECT_EQ(static_cast<unsigned int>(meta.state), state);
        }
    }
}

TEST(MemberStateTest, unknown_persisted_state_is_rejected_for_io) {
    auto queue = rawio::Queue::create(64);
    rawstor::tests::TmpDir dir;
    const auto id = new_id();
    const rawstd::URI location(dir.uri());
    auto slot = run(*queue, rawstor::Slot::create(*queue, location));
    RawstorObjectSpec spec{};
    spec.size = 4096;
    spec.width = 1;
    run(*queue, slot->create(id, 0, spec, RAWSTOR_MEMBER_DATA));
    auto backend = run(*queue, rawstor::Backend::create(*queue, location));
    run(*queue, backend->set_state(
                    id, 0, RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
                    static_cast<RawstorObjectSyncStateValue>(255)
                ));
    run(*queue, backend->close());
    try {
        run(*queue, slot->open({}, id, 0, 0, RawstdUUID{}));
        FAIL() << "Unknown sync state opened for I/O";
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), EILSEQ);
    }
    run(*queue, slot->close());
}

TEST(MemberStateTest, malformed_persisted_metadata_is_not_retried) {
    auto queue = rawio::Queue::create(64);
    rawstor::tests::TmpDir dir;
    const auto id = new_id();
    auto slot =
        run(*queue, rawstor::Slot::create(*queue, rawstd::URI(dir.uri())));
    RawstorObjectSpec spec{};
    spec.size = 4096;
    spec.width = 1;
    run(*queue, slot->create(id, 0, spec, RAWSTOR_MEMBER_DATA));
    const auto path = dir.path() / id_string(id) / "0" / "meta";
    std::ifstream input(path, std::ios::binary);
    const std::string original((std::istreambuf_iterator<char>(input)), {});
    ASSERT_FALSE(original.empty());
    input.close();
    auto write_meta = [&](const std::string& contents) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(contents.data(), contents.size());
        output.close();
        ASSERT_TRUE(output.good());
    };
    for (bool truncated : {false, true}) {
        SCOPED_TRACE(truncated);
        std::string malformed = original;
        malformed[0] = '!';
        if (truncated) {
            malformed.resize(3);
        }
        write_meta(malformed);
        testing::internal::CaptureStderr();
        int error = 0;
        try {
            run(*queue, slot->meta(id, 0, RawstdUUID{}));
        } catch (const std::system_error& e) {
            error = e.code().value();
        }
        const auto log = testing::internal::GetCapturedStderr();
        EXPECT_EQ(error, EILSEQ);
        EXPECT_NE(log.find("Malformed object meta:"), std::string::npos);
        EXPECT_EQ(
            log.find("Malformed object meta:"),
            log.rfind("Malformed object meta:")
        );
        EXPECT_EQ(log.find("retrying"), std::string::npos);
        write_meta(original);
        const auto records = run(*queue, slot->meta(id, 0, RawstdUUID{}));
        ASSERT_EQ(records.size(), 1u);
        EXPECT_EQ(records.front().state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    }
    run(*queue, slot->close());
}
