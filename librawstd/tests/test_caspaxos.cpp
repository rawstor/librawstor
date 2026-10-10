#include <rawstd/caspaxos.hpp>

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

using rawstd::caspaxos::AcceptorState;
using rawstd::caspaxos::Ballot;

using State = AcceptorState<std::string>;

} // namespace

TEST(CasPaxosBallotTest, ordered_by_counter_then_proposer) {
    EXPECT_LT((Ballot{1, 9}), (Ballot{2, 1}));
    EXPECT_LT((Ballot{2, 1}), (Ballot{2, 3}));
    EXPECT_EQ((Ballot{2, 3}), (Ballot{2, 3}));
    EXPECT_LT(Ballot{}, (Ballot{0, 1}));
}

TEST(CasPaxosAcceptorTest, prepare_promises_a_higher_ballot_only) {
    State s;
    EXPECT_TRUE(rawstd::caspaxos::prepare(s, Ballot{1, 1}));
    EXPECT_EQ(s.promised, (Ballot{1, 1}));

    EXPECT_FALSE(rawstd::caspaxos::prepare(s, Ballot{1, 1}));
    EXPECT_FALSE(rawstd::caspaxos::prepare(s, Ballot{0, 7}));
    EXPECT_EQ(s.promised, (Ballot{1, 1}));

    EXPECT_TRUE(rawstd::caspaxos::prepare(s, Ballot{1, 2}));
    EXPECT_EQ(s.promised, (Ballot{1, 2}));
}

TEST(CasPaxosAcceptorTest, accept_after_its_own_prepare) {
    State s;
    ASSERT_TRUE(rawstd::caspaxos::prepare(s, Ballot{1, 1}));
    EXPECT_TRUE(rawstd::caspaxos::accept(s, Ballot{1, 1}, std::string("a")));
    EXPECT_EQ(s.accepted, (Ballot{1, 1}));
    EXPECT_EQ(s.value, "a");
}

TEST(CasPaxosAcceptorTest, accept_refused_below_the_promise) {
    State s;
    ASSERT_TRUE(rawstd::caspaxos::prepare(s, Ballot{2, 1}));
    EXPECT_FALSE(
        rawstd::caspaxos::accept(s, Ballot{1, 5}, std::string("stale"))
    );
    EXPECT_EQ(s.value, "");
    EXPECT_EQ(s.accepted, Ballot{});
}

TEST(CasPaxosAcceptorTest, accept_refused_at_or_below_the_accepted_ballot) {
    State s;
    ASSERT_TRUE(rawstd::caspaxos::accept(s, Ballot{3, 1}, std::string("x")));
    EXPECT_FALSE(rawstd::caspaxos::accept(s, Ballot{3, 1}, std::string("y")));
    EXPECT_FALSE(rawstd::caspaxos::prepare(s, Ballot{3, 1}));
    EXPECT_EQ(s.value, "x");
}

TEST(CasPaxosAcceptorTest, prepare_refused_at_or_below_the_accepted_ballot) {
    // An accept without a prepare of its own (a proposer that kept its
    // ballot) leaves promised == accepted; a later prepare must still be
    // above both.
    State s;
    ASSERT_TRUE(rawstd::caspaxos::accept(s, Ballot{4, 2}, std::string("x")));
    EXPECT_FALSE(rawstd::caspaxos::prepare(s, Ballot{4, 1}));
    EXPECT_TRUE(rawstd::caspaxos::prepare(s, Ballot{5, 1}));
}

TEST(CasPaxosAcceptorTest, accept_promises_the_next_ballot) {
    State s;
    ASSERT_TRUE(rawstd::caspaxos::prepare(s, Ballot{1, 1}));
    ASSERT_TRUE(
        rawstd::caspaxos::accept(
            s, Ballot{1, 1}, std::string("a"), Ballot{2, 1}
        )
    );
    EXPECT_EQ(s.promised, (Ballot{2, 1}));

    // The same proposer's next change skips phase 1...
    EXPECT_TRUE(
        rawstd::caspaxos::accept(
            s, Ballot{2, 1}, std::string("b"), Ballot{3, 1}
        )
    );
    EXPECT_EQ(s.value, "b");

    // ...until another proposer prepares above it.
    ASSERT_TRUE(rawstd::caspaxos::prepare(s, Ballot{3, 2}));
    EXPECT_FALSE(rawstd::caspaxos::accept(s, Ballot{3, 1}, std::string("c")));
    EXPECT_EQ(s.value, "b");
}

TEST(CasPaxosAcceptorTest, majorities_never_decide_two_values) {
    // Two proposers race over three acceptors: P1 prepares on {0, 1},
    // P2 on {1, 2} with a higher ballot. P1's accept can then win only
    // acceptor 0 -- no majority -- while P2's wins a majority.
    std::vector<State> acc(3);
    Ballot b1{1, 1};
    Ballot b2{1, 2};

    ASSERT_TRUE(rawstd::caspaxos::prepare(acc[0], b1));
    ASSERT_TRUE(rawstd::caspaxos::prepare(acc[1], b1));
    ASSERT_TRUE(rawstd::caspaxos::prepare(acc[1], b2));
    ASSERT_TRUE(rawstd::caspaxos::prepare(acc[2], b2));

    int p1 = 0;
    int p2 = 0;
    for (State& s : acc) {
        p1 += rawstd::caspaxos::accept(s, b1, std::string("p1")) ? 1 : 0;
    }
    for (State& s : acc) {
        p2 += rawstd::caspaxos::accept(s, b2, std::string("p2")) ? 1 : 0;
    }
    EXPECT_EQ(p1, 1);
    EXPECT_EQ(p2, 3);
}
