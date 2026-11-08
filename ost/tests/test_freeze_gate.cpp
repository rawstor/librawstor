#include <ost/freeze_gate.hpp>

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <system_error>
#include <thread>

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
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();

    rawstd::Task<void> enter = gate.enter(*queue, id, 0);
    EXPECT_TRUE(run_for(*queue, enter, 1000));
    enter.get();
    gate.leave(id, 0);
}

// The barrier: freeze waits for the admitted write, a write that comes
// after it waits for the thaw, and then goes through.
TEST(FreezeGateTest, freeze_drains_admitted_and_holds_new_writes) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();

    rawstd::Task<void> admitted = gate.enter(*queue, id, 0);
    ASSERT_TRUE(run_for(*queue, admitted, 1000));

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    EXPECT_FALSE(run_for(*queue, freeze, 50))
        << "frozen with a write in flight";

    rawstd::Task<void> late = gate.enter(*queue, id, 0);
    EXPECT_FALSE(run_for(*queue, late, 50)) << "a new write got past";

    // A freeze that is still waiting for writes does not hold the member yet:
    // a version must not be taken under it.
    EXPECT_FALSE(gate.held_by(id, 0, token));

    gate.leave(id, 0);
    EXPECT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();
    EXPECT_TRUE(gate.held_by(id, 0, token));
    EXPECT_FALSE(run_for(*queue, late, 50)) << "a write got past a frozen gate";

    EXPECT_EQ(gate.thaw(id, 0, token), 0);
    EXPECT_TRUE(run_for(*queue, late, 1000));
    late.get();
    gate.leave(id, 0);
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

    rawstd::Task<void> same_object_other_chunk = gate.enter(*queue, id, 4096);
    EXPECT_TRUE(run_for(*queue, same_object_other_chunk, 1000));
    gate.leave(id, 4096);
    rawstd::Task<void> other_object = gate.enter(*queue, other, 0);
    EXPECT_TRUE(run_for(*queue, other_object, 1000));
    gate.leave(other, 0);

    EXPECT_EQ(gate.thaw(id, 0, token), 0);
}

// A holder that never thaws cannot stop the writers for good.
TEST(FreezeGateTest, lease_expiry_thaws_by_itself) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(100));
    ASSERT_TRUE(run_for(*queue, freeze, 1000));
    freeze.get();

    rawstd::Task<void> write = gate.enter(*queue, id, 0);
    EXPECT_TRUE(run_for(*queue, write, 2000)) << "the lease never expired";
    write.get();
    gate.leave(id, 0);

    // The version taken under that barrier is not a consistent point.
    EXPECT_EQ(gate.thaw(id, 0, token), ESTALE);
}

TEST(FreezeGateTest, freeze_times_out_when_writes_never_drain) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();

    rawstd::Task<void> admitted = gate.enter(*queue, id, 0);
    ASSERT_TRUE(run_for(*queue, admitted, 1000));

    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(100));
    ASSERT_TRUE(run_for(*queue, freeze, 2000));
    EXPECT_EQ(error_of(freeze), ETIMEDOUT);

    // It lifted the barrier on the way out.
    EXPECT_FALSE(gate.held_by(id, 0, token));
    rawstd::Task<void> write = gate.enter(*queue, id, 0);
    EXPECT_TRUE(run_for(*queue, write, 1000));
    gate.leave(id, 0);
    gate.leave(id, 0);
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
}

TEST(FreezeGateTest, admission_leaves_with_its_scope) {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(8);
    FreezeGate gate;
    RawstdUUID id = make_uuid();
    RawstdUUID token = make_uuid();
    {
        FreezeAdmission admission;
        rawstd::Task<void> acquire =
            admission.acquire(gate, *queue, id, 0);
        ASSERT_TRUE(run_for(*queue, acquire, 1000));
        acquire.get();
    }
    rawstd::Task<void> freeze =
        gate.freeze(*queue, id, 0, token, milliseconds(10000));
    EXPECT_TRUE(run_for(*queue, freeze, 1000)) << "the admission leaked";
    freeze.get();
    EXPECT_EQ(gate.thaw(id, 0, token), 0);
}
