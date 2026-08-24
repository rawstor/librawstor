#ifndef RAWSTOR_TELEMETRY_HPP
#define RAWSTOR_TELEMETRY_HPP

#include "config.h"

#include <sys/types.h>

#include <chrono>

#include <cstddef>
#include <cstdint>

namespace rawstor {
namespace telemetry {

// A raw nanosecond count -- both a timestamp (now()) and a duration
// (a difference of two timestamps) -- plain enough that call sites
// (SessionOp, Connection::_op) can stamp every op unconditionally without
// an #ifdef, and (unlike a double) exact under subtraction no matter how
// long the process has been up.
using TimePoint = int64_t;

#ifdef RAWSTOR_TELEMETRY

inline TimePoint now() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch()
    )
        .count();
}

#else

// Always 0 here, so a call site's now()/subtraction is a compile-time
// constant an optimizing build (-O1+) discards entirely, instead of
// paying for a real clock read whose result only ever reaches a no-op
// record_*() sink.
inline TimePoint now() noexcept {
    return 0;
}

#endif

#ifdef RAWSTOR_TELEMETRY

// Call-to-completion latency, spanning every retry attempt of one
// Connection data-path/metadata call -- recorded once per call by
// Connection::_finish(), regardless of which backend (ost/blk) it
// eventually succeeded or failed against. Per-attempt telemetry, split by
// backend since what's actually measurable differs between them (e.g.
// blk has no network round-trip to report), lives in the ost/blk
// namespaces below instead.
void record_lat(TimePoint ns);

#else

inline void record_lat(TimePoint) {
}

#endif

// Per-attempt telemetry for rawstor::ost::Session -- one real network
// round-trip per attempt, so slat/rtt/clat are all meaningful.
namespace ost {

#ifdef RAWSTOR_TELEMETRY

void record_slat(TimePoint ns);
void record_rtt(TimePoint ns);
void record_clat(TimePoint ns);
// Called by SessionOp::_dispatch() once slat/rtt/clat are all known for
// this attempt, i.e. after its callback chain returns. `op` is a static
// string (a string literal in the caller), not owned. Feeds the top-N
// slowest-requests report. `lat` here is this single attempt's own span
// (slat+rtt+clat) -- unlike record_lat()'s cross-retry aggregate, it does
// not span retries, since an attempt that gets retried is a new SessionOp
// with no memory of earlier attempts.
void record_op(
    TimePoint lat, TimePoint slat, TimePoint rtt, TimePoint clat,
    const char* op, size_t size, off_t offset
);
void op_started();
void op_finished();
void dump();

#else

inline void record_slat(TimePoint) {
}
inline void record_rtt(TimePoint) {
}
inline void record_clat(TimePoint) {
}
inline void record_op(
    TimePoint, TimePoint, TimePoint, TimePoint, const char*, size_t, off_t
) {
}
inline void op_started() {
}
inline void op_finished() {
}
inline void dump() {
}

#endif

} // namespace ost

// Per-attempt telemetry for rawstor::blk::Session -- a direct fd
// read/write via the io queue, not a request to a remote peer, so there
// is no round-trip to report: slat covers submitting the op to the queue,
// clat covers the (usually negligible) time from completion to the
// caller resuming, and there is no rtt equivalent in between.
namespace blk {

#ifdef RAWSTOR_TELEMETRY

void record_slat(TimePoint ns);
void record_clat(TimePoint ns);
// Same role as ost::record_op(), minus the rtt column blk sessions have
// nothing to report for.
void record_op(
    TimePoint lat, TimePoint slat, TimePoint clat, const char* op, size_t size,
    off_t offset
);
void op_started();
void op_finished();
void dump();

#else

inline void record_slat(TimePoint) {
}
inline void record_clat(TimePoint) {
}
inline void
record_op(TimePoint, TimePoint, TimePoint, const char*, size_t, off_t) {
}
inline void op_started() {
}
inline void op_finished() {
}
inline void dump() {
}

#endif

} // namespace blk

#ifdef RAWSTOR_TELEMETRY

// Prints the shared cross-retry lat stat, then ost::dump() and
// blk::dump() -- called once, from rawstor_terminate().
void dump();

#else

inline void dump() {
}

#endif

} // namespace telemetry
} // namespace rawstor

#endif // RAWSTOR_TELEMETRY_HPP
