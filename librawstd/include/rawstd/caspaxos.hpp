#ifndef RAWSTD_CASPAXOS_HPP
#define RAWSTD_CASPAXOS_HPP

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>

#include <algorithm>
#include <compare>
#include <exception>
#include <limits>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <cerrno>

#include <cstdint>

/*
 * CASPaxos: a single-value register replicated over a set of acceptors,
 * changed by any number of proposers without a leader (Rystsov,
 * "CASPaxos: Replicated State Machines without logs"). A change is decided
 * once a majority of acceptors accepted it.
 *
 * Acceptor rules and coroutine-based proposers are independent of the
 * value type and transport. Acceptors persist their state before replying
 * and include it in every reply, including refusals.
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

// One acceptor's state. Restored from storage before processing requests;
// the caller persists a successful transition before sending its reply.
template <typename V>
class Acceptor final {
private:
    Ballot _promised;
    Ballot _accepted;
    V _value;

public:
    Acceptor(Ballot promised = {}, Ballot accepted = {}, V value = {}) :
        _promised(promised),
        _accepted(accepted),
        _value(std::move(value)) {}

    // A request moves the acceptor's counters forward by at most this much
    // (see within_jump()).
    static constexpr uint64_t max_jump = uint64_t(1) << 28;

    // Whether `ballot` is within reach of the acceptor: its counter is not
    // more than max_jump above the highest the acceptor holds. A proposer
    // raises its counter by one per attempt, from the counters the
    // acceptors report, so a legitimate ballot is as far ahead as the
    // acceptor is behind its peers -- decisions it missed. A request further
    // ahead could only exhaust the counter space: the acceptor would
    // promise it and refuse every ballot below, and no proposer could go on.
    bool within_jump(const Ballot& ballot) const noexcept {
        uint64_t base = std::max(_promised.counter, _accepted.counter);
        return ballot.counter <= base || ballot.counter - base <= max_jump;
    }

    const Ballot& promised() const noexcept { return _promised; }
    const Ballot& accepted() const noexcept { return _accepted; }
    const V& value() const noexcept { return _value; }

    // Promise only a ballot above both the promise and accepted ballot.
    bool prepare(const Ballot& ballot) noexcept {
        if (!(_promised < ballot) || !(_accepted < ballot)) {
            return false;
        }
        _promised = ballot;
        return true;
    }

    // Accept above the accepted ballot and not below the promise. Also
    // promise next, allowing this proposer to skip its next prepare.
    bool accept(const Ballot& ballot, const V& value, const Ballot& next = {}) {
        if (ballot < _promised || !(_accepted < ballot)) {
            return false;
        }
        _value = value;
        _accepted = ballot;
        _promised = ballot < next ? next : ballot;
        return true;
    }
};

// A transport reply includes the actual state even on refusal.
template <typename V>
struct Reply {
    bool ok;
    Acceptor<V> state;
};

// One instance drives one fixed register. Its nonzero id must be unique
// among live proposers; calls must be serialized on the caller's queue.
// Transport supplies Task<Reply<V>> prepare(index, ballot) and
// accept(index, ballot, value, next). Requests must complete or time out.
// A failed change can have reached storage: retry functions must tolerate
// a value already containing their change and must have no side effects.
template <typename V>
class Proposer final {
private:
    struct Result {
        std::optional<Reply<V>> reply;
        std::exception_ptr error;
    };
    struct Round {
        size_t ok = 0;
        bool refused = false;
        std::optional<Acceptor<V>> latest;
    };

    const uint64_t _id;
    const size_t _members;
    uint64_t _counter = 0;
    std::optional<Ballot> _next;
    std::optional<Ballot> _decided;
    std::optional<V> _value;
    bool _busy = false;

    template <typename Request>
    static Task<void> _request(Request request, size_t index, Result& result) {
        try {
            result.reply = co_await request(index);
        } catch (...) {
            result.error = std::current_exception();
        }
    }

    template <typename Request>
    Task<Round> _round(Request request) {
        std::vector<Result> results(_members);
        std::vector<Task<void>> tasks;
        tasks.reserve(_members);
        for (size_t i = 0; i < _members; ++i) {
            tasks.push_back(_request(request, i, results[i]));
        }
        // Drain every request before propagating an error or destroying
        // tasks: other requests may still be using this round's arguments.
        for (auto& task : tasks) {
            co_await task;
        }
        Round round;
        for (const auto& result : results) {
            if (result.error) {
                try {
                    std::rethrow_exception(result.error);
                } catch (const std::system_error& e) {
                    if (e.code().value() == ECANCELED) {
                        throw;
                    }
                }
                continue;
            }
            const Reply<V>& reply = *result.reply;
            _counter = std::max(
                _counter, std::max(
                              reply.state.promised().counter,
                              reply.state.accepted().counter
                          )
            );
            if (!reply.ok) {
                round.refused = true;
                continue;
            }
            ++round.ok;
            if (!round.latest ||
                round.latest->accepted() < reply.state.accepted()) {
                round.latest = reply.state;
            }
        }
        co_return round;
    }

public:
    Proposer(uint64_t id, size_t members) : _id(id), _members(members) {
        if (id == 0 || members == 0) {
            throw std::invalid_argument(
                "CASPaxos needs a proposer id and acceptors"
            );
        }
    }
    Proposer(const Proposer&) = delete;
    Proposer& operator=(const Proposer&) = delete;

    // The ballot of the last decision of this proposer, which an acceptor
    // that missed it can still accept the decided value under.
    const std::optional<Ballot>& decided() const noexcept { return _decided; }

    // Counters seen outside a round (acceptor states read some other way)
    // raise the next ballot above them, saving a refused prepare.
    void observe(const Ballot& ballot) noexcept {
        _counter = std::max(_counter, ballot.counter);
    }

    // The transport and this proposer must outlive the returned task.
    // The change is owned by the coroutine and may be reapplied on a
    // conflict. nullopt means retain the current value; that value still
    // goes through accept to establish a majority decision.
    // No majority: EHOSTUNREACH; exhausted conflict attempts: EAGAIN;
    // exhausted ballot counters: EOVERFLOW; overlapping calls: EBUSY.
    template <typename Transport, typename Change>
    Task<V>
    change(Transport& transport, Change transform, size_t attempts = 16) {
        if (_busy) {
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }
        _busy = true;
        struct Guard {
            bool& busy;
            ~Guard() { busy = false; }
        } guard{_busy};
        std::optional<Ballot> reserved = std::exchange(_next, {});
        for (size_t attempt = 0; attempt < attempts; ++attempt) {
            Ballot ballot;
            std::optional<V> current;
            if (reserved) {
                ballot = *reserved;
                reserved.reset();
                current = _value;
            } else {
                if (_counter >= std::numeric_limits<uint64_t>::max() - 1) {
                    RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
                }
                ballot = Ballot{++_counter, _id};
                Round prepared = co_await _round([&](size_t index) {
                    return transport.prepare(index, ballot);
                });
                if (prepared.ok <= _members / 2) {
                    if (prepared.refused) {
                        continue;
                    }
                    RAWSTD_THROW_SYSTEM_ERROR(EHOSTUNREACH);
                }
                current = prepared.latest->value();
            }
            std::optional<V> changed = transform(*current);
            V value = changed ? std::move(*changed) : std::move(*current);
            if (ballot.counter == std::numeric_limits<uint64_t>::max()) {
                RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
            }
            Ballot next{ballot.counter + 1, _id};
            _counter = std::max(_counter, next.counter);
            Round accepted = co_await _round([&](size_t index) {
                return transport.accept(index, ballot, value, next);
            });
            if (accepted.ok > _members / 2) {
                _value = value;
                _decided = ballot;
                if (!accepted.refused) {
                    _next = next;
                }
                co_return value;
            }
            if (!accepted.refused) {
                RAWSTD_THROW_SYSTEM_ERROR(EHOSTUNREACH);
            }
        }
        RAWSTD_THROW_SYSTEM_ERROR(EAGAIN);
    }
};

} // namespace caspaxos
} // namespace rawstd

#endif // RAWSTD_CASPAXOS_HPP
