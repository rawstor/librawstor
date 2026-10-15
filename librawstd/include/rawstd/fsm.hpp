#ifndef RAWSTD_FSM_HPP
#define RAWSTD_FSM_HPP

#include <rawstd/gpp.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <span>
#include <type_traits>

#include <cerrno>

namespace rawstd {

template <typename State>
struct FsmEdge {
    State from;
    State to;
};

/*
 * The table of a finite state machine over an enum: which transitions
 * exist. It is the single place that says which status changes are allowed,
 * for a machine that lives in memory (Fsm) as well as for a state kept
 * elsewhere, such as a copy's record on a backend, where it guards the
 * transitions asked for.
 *
 * The table is a constant expression; declare it as a constexpr variable
 * with fsm_transitions(). The states can be any values of the enum.
 */
template <typename State, std::size_t N>
class FsmTransitions final {
    static_assert(std::is_enum_v<State>, "Fsm state must be an enum");

private:
    std::array<FsmEdge<State>, N> _edges;

public:
    constexpr explicit FsmTransitions(const FsmEdge<State> (&edges)[N]) :
        _edges{} {
        for (std::size_t i = 0; i < N; ++i) {
            _edges[i] = edges[i];
        }
    }

    constexpr std::span<const FsmEdge<State>> edges() const noexcept {
        return _edges;
    }

    // A state the table does not mention has no transitions.
    constexpr bool allowed(State from, State to) const noexcept {
        for (const FsmEdge<State>& edge : _edges) {
            if (edge.from == from && edge.to == to) {
                return true;
            }
        }
        return false;
    }

    // Throws std::system_error(EINVAL) for a transition outside the table.
    void require(State from, State to) const {
        if (!allowed(from, to)) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
};

template <typename State, std::size_t N>
constexpr FsmTransitions<State, N>
fsm_transitions(const FsmEdge<State> (&edges)[N]) {
    return FsmTransitions<State, N>(edges);
}

/*
 * A finite state machine over an enum: a table of allowed transitions and
 * the current state. state() never blocks and may be read from any thread.
 * Serializing a change with whatever must happen with it (persisting it,
 * for one) is up to the caller's own lock, as the machine takes none.
 *
 * The machine refers to its table, which must outlive it: a constexpr
 * variable.
 */
template <typename State>
class Fsm final {
private:
    std::span<const FsmEdge<State>> _edges;
    std::atomic<State> _state;

    bool _allowed(State from, State to) const noexcept {
        for (const FsmEdge<State>& edge : _edges) {
            if (edge.from == from && edge.to == to) {
                return true;
            }
        }
        return false;
    }

public:
    template <std::size_t N>
    Fsm(State initial, const FsmTransitions<State, N>& transitions) :
        _edges(transitions.edges()),
        _state(initial) {}

    template <std::size_t N>
    Fsm(State, const FsmTransitions<State, N>&&) = delete;

    Fsm(const Fsm&) = delete;
    Fsm& operator=(const Fsm&) = delete;

    State state() const noexcept {
        return _state.load(std::memory_order_acquire);
    }

    bool is(State state) const noexcept { return this->state() == state; }

    bool allowed(State to) const noexcept { return _allowed(state(), to); }

    // Moves to `to`; the table must allow that move from the state the
    // machine is in when the move happens, otherwise this throws
    // std::system_error(EINVAL). A move is validated against the state it
    // replaces, so concurrent set() calls cannot record a move the table
    // does not allow.
    void set(State to) {
        State from = state();
        do {
            if (!_allowed(from, to)) {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        } while (!_state.compare_exchange_weak(
            from, to, std::memory_order_acq_rel, std::memory_order_acquire
        ));
    }

    // Puts the machine in `state` without consulting the table: for
    // (re)initialization from outside, not for a transition.
    void reset(State state) { _state.store(state, std::memory_order_release); }
};

} // namespace rawstd

#endif // RAWSTD_FSM_HPP
