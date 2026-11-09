#include <ost/freeze_gate.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <system_error>
#include <thread>
#include <vector>

#include <cerrno>

namespace {

using rawstor::ostserver::FreezeAdmission;
using rawstor::ostserver::FreezeGate;
using std::chrono::milliseconds;

// Drives `queue` until `task` is done or `msec` passes; tells which.
template <typename T>
bool run_for(rawio::Queue& queue, rawstd::Task<T>& task, unsigned int msec) {
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(msec);
    while (!task.done() && std::chrono::steady_clock::now() < deadline) {
        try {
            queue.wait_timeout(5);
        } catch (const std::system_error& e) {
            if (e.code().value() != ETIME) {
                throw;
            }
        }
    }
    return task.done();
}

RawstdUUID make_uuid() {
    RawstdUUID id;
    EXPECT_EQ(rawstd_uuid7_init(&id), 0);
    return id;
}

int error_of(rawstd::Task<void>& task) {
    try {
        task.get();
    } catch (const std::system_error& e) {
        return e.code().value();
    }
    return 0;
}

} // namespace

TEST(FreezeGateTest, writes_pass_while_not_frozen) {
    FreezeGate gate;
    FreezeGate::MemberRef member = gate.member(make_uuid(), 0);

    // The fast path: no queue, no coroutine.
    EXPECT_TRUE(member->try_enter());
    member->leave();
}

// The same member is the same object for everyone, so a session that looked
// it up once sees a freeze taken by name.
TEST(FreezeGateTest, a_member_is_shared_by_name) {
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    EXPECT_EQ(gate.member(id, 0), gate.member(id, 0));
    EXPECT_NE(gate.member(id, 0), gate.member(id, 4096));
    EXPECT_NE(gate.member(id, 0), gate.member(make_uuid(), 0));
}

// The barrier: freeze waits for the admitted write, a write that comes
// after it waits for the thaw, and then goes through.
TEST(FreezeGateTest, freeze_drains_admitted_and_holds_new_writes) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();
    FreezeGate::MemberRef member = gate.member(id, 0);

    ASSERT_TRUE(member->try_enter());

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    EXPECT_FALSE(run_for(*queue, freeze, 50))
        << "frozen with a write in flight";

    EXPECT_FALSE(member->try_enter()) << "a new write got past";
    rawstd::Task<void> late = member->wait(*queue);
    EXPECT_FALSE(run_for(*queue, late, 50)) << "a new write got past";

    // A freeze that is still waiting for writes does not hold the member yet:
    // a version must not be taken under it.
    EXPECT_FALSE(gate.held_by(id, 0, token));

    member->leave();
    EXPECT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();
    EXPECT_TRUE(gate.held_by(id, 0, token));
    EXPECT_FALSE(run_for(*queue, late, 50)) << "a write got past a frozen gate";

    EXPECT_EQ(gate.thaw(id, 0, token), 0);
    EXPECT_TRUE(run_for(*queue, late, 1000));
    late.get();
    member->leave();
}

// A frozen member nobody holds a reference to is still frozen: the gate keeps
// it, so a session that opens it later finds the barrier.
TEST(FreezeGateTest, a_frozen_member_outlives_its_sessions) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    ASSERT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();

    // Enough other members to make the gate sweep the idle ones.
    for (int i = 0; i < 300; ++i) {
        gate.member(make_uuid(), 0);
    }

    FreezeGate::MemberRef member = gate.member(id, 0);
    EXPECT_FALSE(member->try_enter());
    EXPECT_TRUE(gate.held_by(id, 0, token));
    EXPECT_EQ(gate.thaw(id, 0, token), 0);
    EXPECT_TRUE(member->try_enter());
    member->leave();
}

TEST(FreezeGateTest, other_members_are_not_held) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID other = make_uuid();
    RawstdUUID token = make_uuid();

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    ASSERT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();

    EXPECT_TRUE(gate.member(id, 4096)->try_enter());
    gate.member(id, 4096)->leave();
    EXPECT_TRUE(gate.member(other, 0)->try_enter());
    gate.member(other, 0)->leave();

    EXPECT_EQ(gate.thaw(id, 0, token), 0);
}

// A holder that never thaws cannot stop the writers for good.
TEST(FreezeGateTest, lease_expiry_thaws_by_itself) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();
    FreezeGate::MemberRef member = gate.member(id, 0);

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(100));
    ASSERT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();

    rawstd::Task<void> write = member->wait(*queue);
    EXPECT_TRUE(run_for(*queue, write, 2000)) << "the lease never expired";
    write.get();
    member->leave();

    // The version taken under that barrier is not a consistent point.
    EXPECT_EQ(gate.thaw(id, 0, token), ESTALE);
}

TEST(FreezeGateTest, freeze_times_out_when_writes_never_drain) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();
    FreezeGate::MemberRef member = gate.member(id, 0);

    ASSERT_TRUE(member->try_enter());

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(100));
    ASSERT_TRUE(run_for(*queue, freeze, 2000));
    EXPECT_EQ(error_of(freeze), ETIMEDOUT);

    // It lifted the barrier on the way out.
    EXPECT_FALSE(gate.held_by(id, 0, token));
    EXPECT_TRUE(member->try_enter());
    member->leave();
    member->leave();
}

TEST(FreezeGateTest, a_second_holder_waits_its_turn) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID first = make_uuid();
    RawstdUUID second = make_uuid();

    rawstd::Task<void> freeze1 =
        gate.freeze(*queue, id, 0, first, milliseconds(10000));
    ASSERT_TRUE(run_for(*queue, freeze1, 1000));
    freeze1.get();

    rawstd::Task<void> freeze2 =
        gate.freeze(*queue, id, 0, second, milliseconds(10000));
    EXPECT_FALSE(run_for(*queue, freeze2, 50));
    EXPECT_EQ(gate.thaw(id, 0, second), ESTALE) << "not its barrier to lift";

    EXPECT_EQ(gate.thaw(id, 0, first), 0);
    EXPECT_TRUE(run_for(*queue, freeze2, 1000));
    freeze2.get();
    EXPECT_TRUE(gate.held_by(id, 0, second));
    EXPECT_EQ(gate.thaw(id, 0, second), 0);
}

TEST(FreezeGateTest, the_same_token_renews_its_freeze) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(150));
    ASSERT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();
    std::this_thread::sleep_for(milliseconds(100));
    rawstd::Task<void> renew =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    ASSERT_TRUE(run_for(*queue, renew, 1000));
    renew.get();
    std::this_thread::sleep_for(milliseconds(100));
    EXPECT_TRUE(gate.held_by(id, 0, token));
    EXPECT_EQ(gate.thaw(id, 0, token), 0);
}

TEST(FreezeGateTest, thaw_without_freeze_is_stale) {
    FreezeGate gate;
    EXPECT_EQ(gate.thaw(make_uuid(), 0, make_uuid()), ESTALE);
    EXPECT_FALSE(gate.held_by(make_uuid(), 0, make_uuid()));
}

TEST(FreezeGateTest, admission_leaves_with_its_scope) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();
    FreezeGate::MemberRef member = gate.member(id, 0);
    {
        FreezeAdmission admission;
        ASSERT_TRUE(admission.try_enter(*member));
    }
    {
        // The slow path, taken by a write that met a frozen member.
        rawstd::Task<void> freeze =
            gate.freeze(*queue, id, 0, token, milliseconds(10000));
        ASSERT_TRUE(run_for(*queue, freeze, 1000));
        freeze.get();

        FreezeAdmission admission;
        EXPECT_FALSE(admission.try_enter(*member));
        rawstd::Task<void> wait = admission.wait(*member, *queue);
        EXPECT_FALSE(run_for(*queue, wait, 50));
        EXPECT_EQ(gate.thaw(id, 0, token), 0);
        ASSERT_TRUE(run_for(*queue, wait, 1000));
        wait.get();
    }
    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    EXPECT_TRUE(run_for(*queue, freeze, 1000)) << "the admission leaked";
    freeze.get();
    EXPECT_EQ(gate.thaw(id, 0, token), 0);
}

// Writers on several threads against a freeze/thaw cycle: whenever the freeze
// answers, no write is in flight and none starts until the thaw.
TEST(FreezeGateTest, concurrent_writers_never_overlap_a_frozen_member) {
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    FreezeGate::MemberRef member = gate.member(id, 0);
    std::atomic<bool> stop{false};
    std::atomic<int> inside{0};
    std::atomic<int> violations{0};
    std::atomic<bool> held{false};

    std::vector<std::thread> writers;
    for (int t = 0; t < 3; ++t) {
        writers.emplace_back([&]() {
            while (!stop.load()) {
                if (member->try_enter()) {
                    inside.fetch_add(1);
                    if (held.load()) {
                        violations.fetch_add(1);
                    }
                    inside.fetch_sub(1);
                    member->leave();
                }
            }
        });
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    for (int round = 0; round < 50; ++round) {
        RawstdUUID token = make_uuid();
        rawstd::Task<void> freeze =
            gate.freeze(*queue, id, 0, token, milliseconds(10000));
        ASSERT_TRUE(run_for(*queue, freeze, 5000));
        freeze.get();
        held.store(true);
        // The freeze answered: nothing is in flight and nothing may start.
        EXPECT_EQ(inside.load(), 0);
        std::this_thread::sleep_for(milliseconds(2));
        EXPECT_EQ(inside.load(), 0);
        held.store(false);
        EXPECT_EQ(gate.thaw(id, 0, token), 0);
        std::this_thread::sleep_for(milliseconds(1));
    }
    stop.store(true);
    for (auto& w : writers) {
        w.join();
    }
    EXPECT_EQ(violations.load(), 0);
}
