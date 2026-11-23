#include "backend.hpp"
#include "meta_cache.hpp"
#include "opts.h"
#include "owner.hpp"
#include "slot.hpp"
#include "tmp_dir.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <thread>

/*
 * The records a rawstor-ost keeps in memory (MetaCache): what a Slot that
 * has one answers, and when it asks the backend again.
 */

namespace {

using namespace std::chrono_literals;

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

RawstorObjectMeta record(RawstorObjectSyncStateValue state) {
    RawstorObjectMeta meta{};
    meta.state = state;
    return meta;
}

// The ttl is long for the tests that must not see an expiry.
constexpr std::chrono::milliseconds long_ttl = 1h;

} // namespace

TEST(MetaCacheTest, a_record_filled_after_a_miss_is_found) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;
    EXPECT_FALSE(cache.find(id, 0, ticket));
    cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_DIRTY)});

    rawstor::MetaCache::Ticket other;
    auto found = cache.find(id, 0, other);
    ASSERT_TRUE(found);
    ASSERT_EQ(found->size(), 1u);
    EXPECT_EQ(found->front().state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    // Another chunk of the same object, and another object, are not it.
    EXPECT_FALSE(cache.find(id, 1u << 20, other));
    EXPECT_FALSE(cache.find(new_id(), 0, other));
}

TEST(MetaCacheTest, a_write_erases_the_record_before_and_after_it) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;
    cache.find(id, 0, ticket);
    cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});

    {
        rawstor::MetaCache::Write write(&cache, id, 0);
        EXPECT_FALSE(cache.find(id, 0, ticket));
    }
    EXPECT_FALSE(cache.find(id, 0, ticket));
}

TEST(MetaCacheTest, a_write_of_one_chunk_leaves_the_others_alone) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;
    cache.find(id, 0, ticket);
    cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    cache.find(id, 4096, ticket);
    cache.fill(id, 4096, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});

    { rawstor::MetaCache::Write write(&cache, id, 0); }
    EXPECT_FALSE(cache.find(id, 0, ticket));
    EXPECT_TRUE(cache.find(id, 4096, ticket));
}

TEST(MetaCacheTest, a_write_without_a_cache_is_nothing) {
    rawstor::MetaCache::Write write(nullptr, new_id(), 0);
}

// A read of the backend that began before a write, or ended after it, may
// hold the record from before it.
TEST(MetaCacheTest, a_read_that_overlaps_a_write_is_not_stored) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();

    rawstor::MetaCache::Ticket before;
    cache.find(id, 0, before);
    { rawstor::MetaCache::Write write(&cache, id, 0); }
    cache.fill(id, 0, before, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    rawstor::MetaCache::Ticket ticket;
    EXPECT_FALSE(cache.find(id, 0, ticket));

    rawstor::MetaCache::Ticket during;
    {
        rawstor::MetaCache::Write write(&cache, id, 0);
        cache.find(id, 0, during);
    }
    cache.fill(id, 0, during, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    EXPECT_FALSE(cache.find(id, 0, ticket));

    // A read that began after the write is stored.
    cache.find(id, 0, ticket);
    cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    EXPECT_TRUE(cache.find(id, 0, ticket));
}

// A read that begins and ends inside a write holds what the backend has in
// the middle of the change: it is not stored, and nothing is answered from
// the cache until the write ends.
TEST(MetaCacheTest, a_record_is_neither_found_nor_stored_during_a_write) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;

    {
        rawstor::MetaCache::Write write(&cache, id, 0);
        EXPECT_FALSE(cache.find(id, 0, ticket));
        cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
        EXPECT_FALSE(cache.find(id, 0, ticket));
    }
    EXPECT_FALSE(cache.find(id, 0, ticket));
}

TEST(MetaCacheTest, overlapping_writes_of_a_record_hold_it_until_the_last) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;

    auto first = std::make_unique<rawstor::MetaCache::Write>(&cache, id, 0);
    auto second = std::make_unique<rawstor::MetaCache::Write>(&cache, id, 0);
    first.reset();
    EXPECT_FALSE(cache.find(id, 0, ticket));
    EXPECT_FALSE(ticket.fillable);
    second.reset();

    // Nothing holds it now.
    EXPECT_FALSE(cache.find(id, 0, ticket));
    EXPECT_TRUE(ticket.fillable);
    cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    EXPECT_TRUE(cache.find(id, 0, ticket));
}

TEST(MetaCacheTest, a_write_of_one_chunk_does_not_hold_the_others) {
    rawstor::MetaCache cache(long_ttl);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;

    rawstor::MetaCache::Write write(&cache, id, 0);
    EXPECT_FALSE(cache.find(id, 4096, ticket));
    EXPECT_TRUE(ticket.fillable);
    cache.fill(id, 4096, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    EXPECT_TRUE(cache.find(id, 4096, ticket));
}

TEST(MetaCacheTest, a_record_expires_after_its_time_to_live) {
    rawstor::MetaCache cache(30ms);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;
    cache.find(id, 0, ticket);
    cache.fill(id, 0, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});
    EXPECT_TRUE(cache.find(id, 0, ticket));
    std::this_thread::sleep_for(60ms);
    EXPECT_FALSE(cache.find(id, 0, ticket));
}

TEST(MetaCacheTest, the_least_recently_used_record_goes_at_capacity) {
    rawstor::MetaCache cache(long_ttl, 2);
    const RawstdUUID id = new_id();
    rawstor::MetaCache::Ticket ticket;
    for (uint64_t offset : {0u, 4096u}) {
        cache.find(id, offset, ticket);
        cache.fill(
            id, offset, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)}
        );
    }
    // Reading the first makes the second the least recently used.
    EXPECT_TRUE(cache.find(id, 0, ticket));
    cache.find(id, 8192, ticket);
    cache.fill(id, 8192, ticket, {record(RAWSTOR_OBJECT_SYNC_STATE_CLEAN)});

    EXPECT_TRUE(cache.find(id, 0, ticket));
    EXPECT_FALSE(cache.find(id, 4096, ticket));
    EXPECT_TRUE(cache.find(id, 8192, ticket));
}

namespace {

// A file:// store in a directory of its own, with one chunk created.
struct Store {
    rawstor::tests::TmpDir dir;
    RawstdUUID id = new_id();
    rawstd::URI location{dir.uri()};

    void create(rawio::Queue& queue) {
        auto slot = run(queue, rawstor::Slot::create(queue, location));
        RawstorObjectSpec spec{};
        spec.size = 4096;
        spec.width = 1;
        run(queue, slot->create(
                       id, 0, spec, RAWSTOR_MEMBER_DATA,
                       rawstor::tests::default_owner()
                   ));
        run(queue, slot->close());
    }

    // A change of the record that no Slot of the cache makes.
    void mark_dirty_behind_the_cache(rawio::Queue& queue) {
        auto backend = run(queue, rawstor::Backend::create(queue, location));
        run(queue, backend->set_state(
                       id, 0, RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
                       RAWSTOR_OBJECT_SYNC_STATE_DIRTY
                   ));
        run(queue, backend->close());
    }
};

RawstorObjectSyncStateValue state_of(
    rawio::Queue& queue, rawstor::Slot& slot, const RawstdUUID& id
) {
    return run(queue, slot.meta(id, 0)).front().state;
}

} // namespace

// Two connections of one OST: what one writes the other reads at once, not
// after the record's time to live.
TEST(SlotMetaCacheTest, the_slots_of_one_cache_see_each_others_changes) {
    auto queue = rawio::Queue::create(64);
    Store store;
    store.create(*queue);
    auto cache = std::make_shared<rawstor::MetaCache>(long_ttl);

    auto reader =
        run(*queue, rawstor::Slot::create(*queue, store.location, cache));
    auto writer =
        run(*queue, rawstor::Slot::create(*queue, store.location, cache));
    EXPECT_EQ(
        state_of(*queue, *reader, store.id), RAWSTOR_OBJECT_SYNC_STATE_CLEAN
    );

    run(*queue, writer->open({}, store.id, 0, 0, RawstdUUID{}));
    const char data[] = "ping";
    run(*queue, writer->pwrite(data, sizeof(data), 0, false, 0));
    EXPECT_EQ(
        state_of(*queue, *reader, store.id), RAWSTOR_OBJECT_SYNC_STATE_DIRTY
    );

    run(*queue, writer->close());
    run(*queue, reader->close());
}

// A change made behind the cache is not seen until the record expires:
// what the time to live bounds.
TEST(SlotMetaCacheTest, a_change_behind_the_cache_is_seen_after_the_ttl) {
    auto queue = rawio::Queue::create(64);
    Store store;
    store.create(*queue);
    auto cache = std::make_shared<rawstor::MetaCache>(80ms);

    auto slot =
        run(*queue, rawstor::Slot::create(*queue, store.location, cache));
    EXPECT_EQ(
        state_of(*queue, *slot, store.id), RAWSTOR_OBJECT_SYNC_STATE_CLEAN
    );
    store.mark_dirty_behind_the_cache(*queue);
    EXPECT_EQ(
        state_of(*queue, *slot, store.id), RAWSTOR_OBJECT_SYNC_STATE_CLEAN
    );
    std::this_thread::sleep_for(160ms);
    EXPECT_EQ(
        state_of(*queue, *slot, store.id), RAWSTOR_OBJECT_SYNC_STATE_DIRTY
    );
    run(*queue, slot->close());
}

TEST(SlotMetaCacheTest, a_slot_without_a_cache_reads_the_backend_each_time) {
    auto queue = rawio::Queue::create(64);
    Store store;
    store.create(*queue);

    auto slot = run(*queue, rawstor::Slot::create(*queue, store.location));
    EXPECT_EQ(
        state_of(*queue, *slot, store.id), RAWSTOR_OBJECT_SYNC_STATE_CLEAN
    );
    store.mark_dirty_behind_the_cache(*queue);
    EXPECT_EQ(
        state_of(*queue, *slot, store.id), RAWSTOR_OBJECT_SYNC_STATE_DIRTY
    );
    run(*queue, slot->close());
}

// The writers of this process are not in the record the backend reports:
// they come from the sessions open now, on every read.
TEST(SlotMetaCacheTest, writers_come_from_the_open_sessions_not_the_cache) {
    auto queue = rawio::Queue::create(64);
    Store store;
    store.create(*queue);
    auto cache = std::make_shared<rawstor::MetaCache>(long_ttl);

    auto reader =
        run(*queue, rawstor::Slot::create(*queue, store.location, cache));
    EXPECT_EQ(run(*queue, reader->meta(store.id, 0)).front().writers, 0u);

    auto writer =
        run(*queue, rawstor::Slot::create(*queue, store.location, cache));
    run(*queue, writer->open({}, store.id, 0, 0, RawstdUUID{}));
    EXPECT_EQ(run(*queue, reader->meta(store.id, 0)).front().writers, 1u);

    run(*queue, writer->close());
    EXPECT_EQ(run(*queue, reader->meta(store.id, 0)).front().writers, 0u);
    run(*queue, reader->close());
}

TEST(SlotMetaCacheTest, a_removed_chunk_is_not_answered_from_the_cache) {
    auto queue = rawio::Queue::create(64);
    Store store;
    store.create(*queue);
    auto cache = std::make_shared<rawstor::MetaCache>(long_ttl);

    auto slot =
        run(*queue, rawstor::Slot::create(*queue, store.location, cache));
    EXPECT_EQ(
        state_of(*queue, *slot, store.id), RAWSTOR_OBJECT_SYNC_STATE_CLEAN
    );
    run(*queue, slot->remove(store.id, 0));
    EXPECT_THROW(state_of(*queue, *slot, store.id), std::system_error);
    run(*queue, slot->close());
}
