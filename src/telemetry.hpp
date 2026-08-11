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

// One slow-op sample, for the top-10 report. `lat` is in nanoseconds.
// `op` is a static string (__FUNCTION__), not owned.
struct SlowOp {
    TimePoint lat;
    const char* op;
    size_t size;
    off_t offset;
    unsigned int retries;

    // Deliberately reversed (bigger lat sorts first): lets TopN drive
    // std::push_heap/pop_heap/sort with the default comparator, no
    // separate predicate needed.
    bool operator<(const SlowOp& other) const noexcept {
        return lat > other.lat;
    }
};

#ifdef RAWSTOR_TELEMETRY

void record_slat(TimePoint ns);
void record_rtt(TimePoint ns);
void record_clat(TimePoint ns);
void record_lat(TimePoint ns, unsigned int retries);
void record_op(const SlowOp& op);
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
inline void record_lat(TimePoint, unsigned int) {
}
inline void record_op(const SlowOp&) {
}
inline void op_started() {
}
inline void op_finished() {
}
inline void dump() {
}

#endif

} // namespace telemetry
} // namespace rawstor

#endif // RAWSTOR_TELEMETRY_HPP
