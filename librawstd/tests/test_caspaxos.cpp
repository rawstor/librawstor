#include <rawstd/caspaxos.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <limits>
#include <optional>
#include <system_error>

#include <cerrno>

#include <string>
#include <vector>

namespace {

using rawstd::caspaxos::Acceptor;
using rawstd::caspaxos::Ballot;

using State = Acceptor<std::string>;

} // namespace

TEST(CasPaxosBallotTest, ordered_by_counter_then_proposer) {
    EXPECT_LT((Ballot{1, 9}), (Ballot{2, 1}));
    EXPECT_LT((Ballot{2, 1}), (Ballot{2, 3}));
    EXPECT_EQ((Ballot{2, 3}), (Ballot{2, 3}));
    EXPECT_LT(Ballot{}, (Ballot{0, 1}));
}

TEST(CasPaxosAcceptorTest, prepare_promises_a_higher_ballot_only) {
    State s;
    EXPECT_TRUE(s.prepare(Ballot{1, 1}));
    EXPECT_EQ(s.promised(), (Ballot{1, 1}));

    EXPECT_FALSE(s.prepare(Ballot{1, 1}));
    EXPECT_FALSE(s.prepare(Ballot{0, 7}));
    EXPECT_EQ(s.promised(), (Ballot{1, 1}));

    EXPECT_TRUE(s.prepare(Ballot{1, 2}));
    EXPECT_EQ(s.promised(), (Ballot{1, 2}));
}

TEST(CasPaxosAcceptorTest, accept_after_its_own_prepare) {
    State s;
    ASSERT_TRUE(s.prepare(Ballot{1, 1}));
    EXPECT_TRUE(s.accept(Ballot{1, 1}, std::string("a")));
    EXPECT_EQ(s.accepted(), (Ballot{1, 1}));
    EXPECT_EQ(s.value(), "a");
}

TEST(CasPaxosAcceptorTest, accept_refused_below_the_promise) {
    State s;
    ASSERT_TRUE(s.prepare(Ballot{2, 1}));
    EXPECT_FALSE(s.accept(Ballot{1, 5}, std::string("stale")));
    EXPECT_EQ(s.value(), "");
    EXPECT_EQ(s.accepted(), Ballot{});
}

TEST(CasPaxosAcceptorTest, accept_refused_at_or_below_the_accepted_ballot) {
    State s;
    ASSERT_TRUE(s.accept(Ballot{3, 1}, std::string("x")));
    EXPECT_FALSE(s.accept(Ballot{3, 1}, std::string("y")));
    EXPECT_FALSE(s.prepare(Ballot{3, 1}));
    EXPECT_EQ(s.value(), "x");
}

TEST(CasPaxosAcceptorTest, prepare_refused_at_or_below_the_accepted_ballot) {
    // An accept without a prepare of its own (a proposer that kept its
    // ballot) leaves promised == accepted; a later prepare must still be
    // above both.
    State s;
    ASSERT_TRUE(s.accept(Ballot{4, 2}, std::string("x")));
    EXPECT_FALSE(s.prepare(Ballot{4, 1}));
    EXPECT_TRUE(s.prepare(Ballot{5, 1}));
}

TEST(CasPaxosAcceptorTest, accept_promises_the_next_ballot) {
    State s;
    ASSERT_TRUE(s.prepare(Ballot{1, 1}));
    ASSERT_TRUE(s.accept(Ballot{1, 1}, std::string("a"), Ballot{2, 1}));
    EXPECT_EQ(s.promised(), (Ballot{2, 1}));

    // The same proposer's next change skips phase 1...
    EXPECT_TRUE(s.accept(Ballot{2, 1}, std::string("b"), Ballot{3, 1}));
    EXPECT_EQ(s.value(), "b");

    // ...until another proposer prepares above it.
    ASSERT_TRUE(s.prepare(Ballot{3, 2}));
    EXPECT_FALSE(s.accept(Ballot{3, 1}, std::string("c")));
    EXPECT_EQ(s.value(), "b");
}

TEST(CasPaxosAcceptorTest, majorities_never_decide_two_values) {
    // Two proposers race over three acceptors: P1 prepares on {0, 1},
    // P2 on {1, 2} with a higher ballot. P1's accept can then win only
    // acceptor 0 -- no majority -- while P2's wins a majority.
    std::vector<State> acc(3);
    Ballot b1{1, 1};
    Ballot b2{1, 2};

    ASSERT_TRUE(acc[0].prepare(b1));
    ASSERT_TRUE(acc[1].prepare(b1));
    ASSERT_TRUE(acc[1].prepare(b2));
    ASSERT_TRUE(acc[2].prepare(b2));

    int p1 = 0;
    int p2 = 0;
    for (State& s : acc) {
        p1 += s.accept(b1, std::string("p1")) ? 1 : 0;
    }
    for (State& s : acc) {
        p2 += s.accept(b2, std::string("p2")) ? 1 : 0;
    }
    EXPECT_EQ(p1, 1);
    EXPECT_EQ(p2, 3);
}

namespace {

using IntState = Acceptor<int>;
using IntReply = rawstd::caspaxos::Reply<int>;
using IntProposer = rawstd::caspaxos::Proposer<int>;

struct MemoryTransport {
    std::vector<IntState> states{3};
    std::vector<bool> unavailable{false, false, false};
    std::vector<bool> lose_accept_reply{false, false, false};
    std::function<void(size_t)> before_accept;
    size_t prepares = 0;
    size_t accepts = 0;

    rawstd::Task<IntReply> prepare(size_t index, Ballot ballot) {
        ++prepares;
        if (unavailable[index]) {
            throw std::system_error(ETIMEDOUT, std::generic_category());
        }
        bool ok = states[index].prepare(ballot);
        co_return IntReply{ok, states[index]};
    }

    rawstd::Task<IntReply>
    accept(size_t index, Ballot ballot, int value, Ballot next) {
        ++accepts;
        if (unavailable[index]) {
            throw std::system_error(ETIMEDOUT, std::generic_category());
        }
        if (before_accept) {
            before_accept(index);
        }
        bool ok = states[index].accept(ballot, value, next);
        if (lose_accept_reply[index]) {
            throw std::system_error(ETIMEDOUT, std::generic_category());
        }
        co_return IntReply{ok, states[index]};
    }
};

std::optional<int> increment(int value) {
    return value + 1;
}
std::optional<int> keep(int) {
    return std::nullopt;
}

void expect_error(rawstd::Task<int> task, int error) {
    ASSERT_TRUE(task.done());
    try {
        task.get();
        ADD_FAILURE() << "expected error " << error;
    } catch (const std::system_error& e) {
        EXPECT_EQ(e.code().value(), error);
    }
}

} // namespace

TEST(CasPaxosProposerTest, decides_and_then_skips_prepare) {
    MemoryTransport transport;
    IntProposer proposer(1, 3);
    EXPECT_EQ(proposer.change(transport, increment).get(), 1);
    EXPECT_EQ(transport.prepares, 3u);
    EXPECT_EQ(proposer.change(transport, increment).get(), 2);
    EXPECT_EQ(transport.prepares, 3u);
    EXPECT_EQ(transport.accepts, 6u);
    for (const auto& state : transport.states) {
        EXPECT_EQ(state.value(), 2);
        EXPECT_GT(state.promised(), state.accepted());
    }
}

TEST(CasPaxosProposerTest, observed_counter_saves_a_refused_prepare) {
    MemoryTransport transport;
    transport.states[0] = {{7, 9}, {}, 0};
    transport.states[1] = {{7, 9}, {}, 0};
    transport.states[2] = {{7, 9}, {}, 0};
    IntProposer proposer(1, 3);
    proposer.observe({7, 9});
    EXPECT_EQ(proposer.change(transport, increment).get(), 1);
    EXPECT_EQ(transport.prepares, 3u);
    for (const auto& state : transport.states) {
        EXPECT_GT(state.accepted(), (Ballot{7, 9}));
    }
}

TEST(
    CasPaxosProposerTest, highest_accepted_value_and_unchanged_value_are_decided
) {
    MemoryTransport transport;
    transport.states[0] = {{7, 9}, {7, 9}, 41};
    transport.states[1] = {{4, 9}, {4, 9}, 12};
    IntProposer proposer(1, 3);
    EXPECT_EQ(proposer.change(transport, keep).get(), 41);
    for (const auto& state : transport.states) {
        EXPECT_EQ(state.value(), 41);
        EXPECT_GT(state.accepted(), (Ballot{7, 9}));
    }
}

TEST(CasPaxosProposerTest, accepts_with_a_majority_despite_a_lost_reply) {
    MemoryTransport transport;
    transport.lose_accept_reply[2] = true;
    IntProposer proposer(1, 3);
    EXPECT_EQ(proposer.change(transport, increment).get(), 1);
    EXPECT_EQ(transport.states[2].value(), 1);
}

TEST(CasPaxosProposerTest, unavailable_majority_fails_in_each_phase) {
    MemoryTransport transport;
    transport.unavailable = {true, true, false};
    IntProposer proposer(1, 3);
    expect_error(proposer.change(transport, increment), EHOSTUNREACH);
    EXPECT_EQ(transport.accepts, 0u);

    transport.unavailable = {false, false, false};
    transport.lose_accept_reply = {true, true, false};
    expect_error(proposer.change(transport, increment), EHOSTUNREACH);
    // The uncertain operation must not keep a one-round reservation.
    transport.lose_accept_reply = {false, false, false};
    size_t prepares = transport.prepares;
    EXPECT_EQ(proposer.change(transport, keep).get(), 1);
    EXPECT_GT(transport.prepares, prepares);
}

TEST(CasPaxosProposerTest, competing_proposer_invalidates_one_round_value) {
    MemoryTransport transport;
    IntProposer first(1, 3);
    IntProposer second(2, 3);
    EXPECT_EQ(first.change(transport, increment).get(), 1);
    EXPECT_EQ(second.change(transport, increment).get(), 2);
    size_t prepares = transport.prepares;
    EXPECT_EQ(first.change(transport, increment).get(), 3);
    EXPECT_GT(transport.prepares, prepares);
    for (const auto& state : transport.states) {
        EXPECT_EQ(state.value(), 3);
    }
}

TEST(
    CasPaxosProposerTest, unchanged_cached_value_cannot_hide_a_competing_change
) {
    MemoryTransport transport;
    IntProposer first(1, 3);
    IntProposer second(2, 3);
    EXPECT_EQ(first.change(transport, increment).get(), 1);
    EXPECT_EQ(second.change(transport, increment).get(), 2);
    EXPECT_EQ(first.change(transport, keep).get(), 2);
}

TEST(CasPaxosProposerTest, reapply_change_after_a_conflict_between_phases) {
    MemoryTransport transport;
    IntProposer first(1, 3);
    IntProposer second(2, 3);
    bool interfered = false;
    transport.before_accept = [&](size_t) {
        if (!interfered) {
            interfered = true;
            EXPECT_EQ(second.change(transport, increment).get(), 1);
        }
    };
    EXPECT_EQ(first.change(transport, increment).get(), 2);
    for (const auto& state : transport.states) {
        EXPECT_EQ(state.value(), 2);
    }
}

TEST(CasPaxosProposerTest, repeated_conflicts_are_bounded) {
    MemoryTransport transport;
    transport.before_accept = [&](size_t index) {
        auto& state = transport.states[index];
        state.prepare(Ballot{state.promised().counter + 10, 9});
    };
    IntProposer proposer(1, 3);
    expect_error(proposer.change(transport, increment, 2), EAGAIN);
    EXPECT_EQ(transport.accepts, 6u);
}

TEST(CasPaxosProposerTest, counter_overflow_and_invalid_identity_are_rejected) {
    EXPECT_THROW(IntProposer(0, 3), std::invalid_argument);
    EXPECT_THROW(IntProposer(1, 0), std::invalid_argument);
    MemoryTransport transport;
    transport.states[0].prepare(
        Ballot{std::numeric_limits<uint64_t>::max(), 9}
    );
    transport.states[1].prepare(transport.states[0].promised());
    IntProposer proposer(1, 3);
    expect_error(proposer.change(transport, increment), EOVERFLOW);
}

namespace {

struct DeferredTransport : MemoryTransport {
    std::vector<std::coroutine_handle<>> pending;
    std::optional<size_t> fatal_prepare;

    struct Wait {
        DeferredTransport& transport;
        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> handle) {
            transport.pending.push_back(handle);
        }
        void await_resume() const noexcept {}
    };

    rawstd::Task<IntReply> prepare(size_t index, Ballot ballot) {
        co_await Wait{*this};
        if (fatal_prepare == index) {
            throw std::runtime_error("transport failed");
        }
        co_return co_await MemoryTransport::prepare(index, ballot);
    }
    rawstd::Task<IntReply>
    accept(size_t index, Ballot ballot, int value, Ballot next) {
        co_await Wait{*this};
        co_return co_await MemoryTransport::accept(index, ballot, value, next);
    }
    void resume_last() {
        auto handle = pending.back();
        pending.pop_back();
        handle.resume();
    }
    void drain() {
        size_t limit = 1000;
        while (!pending.empty() && limit-- != 0) {
            resume_last();
        }
        ASSERT_TRUE(pending.empty());
    }
};

} // namespace

TEST(CasPaxosProposerTest, fans_out_and_drains_out_of_order_completions) {
    DeferredTransport transport;
    IntProposer proposer(1, 3);
    auto task = proposer.change(transport, increment);
    ASSERT_FALSE(task.done());
    ASSERT_EQ(transport.pending.size(), 3u);
    expect_error(proposer.change(transport, increment), EBUSY);
    transport.resume_last();
    transport.resume_last();
    EXPECT_FALSE(task.done());
    transport.resume_last();
    ASSERT_EQ(transport.pending.size(), 3u);
    transport.drain();
    ASSERT_TRUE(task.done());
    EXPECT_EQ(task.get(), 1);
}

TEST(CasPaxosProposerTest, concurrent_proposers_preserve_both_changes) {
    DeferredTransport transport;
    IntProposer first(1, 3);
    IntProposer second(2, 3);
    auto a = first.change(transport, increment);
    auto b = second.change(transport, increment);
    ASSERT_EQ(transport.pending.size(), 6u);
    transport.drain();
    ASSERT_TRUE(a.done());
    ASSERT_TRUE(b.done());
    EXPECT_EQ(b.get(), 1);
    EXPECT_EQ(a.get(), 2);
    for (const auto& state : transport.states) {
        EXPECT_EQ(state.value(), 2);
    }
}

TEST(CasPaxosProposerTest, fatal_transport_error_waits_for_other_requests) {
    DeferredTransport transport;
    transport.fatal_prepare = 2;
    IntProposer proposer(1, 3);
    auto task = proposer.change(transport, increment);
    transport.resume_last();
    ASSERT_FALSE(task.done());
    ASSERT_EQ(transport.pending.size(), 2u);
    transport.drain();
    ASSERT_TRUE(task.done());
    EXPECT_THROW(task.get(), std::runtime_error);
    transport.fatal_prepare.reset();
    auto retry = proposer.change(transport, increment);
    transport.drain();
    EXPECT_EQ(retry.get(), 1);
}
