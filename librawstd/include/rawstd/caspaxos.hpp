#ifndef RAWSTD_CASPAXOS_HPP
#define RAWSTD_CASPAXOS_HPP

#include <compare>

#include <cstdint>

/*
 * CASPaxos: a single-value register replicated over a set of acceptors,
 * changed by any number of proposers without a leader (Rystsov,
 * "CASPaxos: Replicated State Machines without logs"). A change is decided
 * once a majority of acceptors accepted it.
 *
 * This header holds the acceptor side: the rules every acceptor applies to
 * the state it stores, as pure functions, independent of the value type and
 * of how requests reach the acceptor. An acceptor persists the state these
 * leave behind before it replies, and replies with that state whether the
 * request succeeded or not: the proposer learns the actual value from the
 * reply.
 */

namespace rawstd {
namespace caspaxos {

// A proposal number. Compared by counter, then by proposer id, so two
// proposers never share one. The default (all zero) is below every
// ballot a proposer uses.
struct Ballot {
    uint64_t counter = 0;
    uint64_t proposer = 0;

    auto operator<=>(const Ballot&) const = default;
};

// What one acceptor stores: the highest ballot it promised, and the value
// with the ballot it was accepted under.
template <typename V>
struct AcceptorState {
    Ballot promised;
    Ballot accepted;
    V value{};
};

// Phase 1: promises `ballot` if it is above both the ballot promised and
// the ballot accepted so far. Returns whether it did; `state` is updated in
// place only then.
template <typename V>
bool prepare(AcceptorState<V>& state, const Ballot& ballot) noexcept {
    if (!(state.promised < ballot) || !(state.accepted < ballot)) {
        return false;
    }
    state.promised = ballot;
    return true;
}

// Phase 2: accepts `value` under `ballot` if `ballot` is not below the
// ballot promised and above the ballot accepted so far. On success the
// acceptor also promises `next` when it is above `ballot`: the proposer's
// next change can then skip phase 1 and go straight to accept with `next`,
// as long as no other proposer prepared in between. Returns whether the
// value was accepted; `state` is updated in place only then.
template <typename V>
bool accept(
    AcceptorState<V>& state, const Ballot& ballot, const V& value,
    const Ballot& next = Ballot{}
) {
    if (ballot < state.promised || !(state.accepted < ballot)) {
        return false;
    }
    state.accepted = ballot;
    state.value = value;
    state.promised = ballot < next ? next : ballot;
    return true;
}

} // namespace caspaxos
} // namespace rawstd

#endif // RAWSTD_CASPAXOS_HPP
