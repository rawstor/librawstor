#ifndef RAWSTOR_TELEMETRY_HPP
#define RAWSTOR_TELEMETRY_HPP

#include "config.h"

#include <sys/types.h>

#include <chrono>

#include <cstddef>

namespace rawstor {
namespace telemetry {

#ifdef RAWSTOR_TELEMETRY

using clock = std::chrono::steady_clock;

#else

// Call sites (SessionOp, Connection::_op) timestamp every op unconditionally
// -- #ifdef'ing each one out would make them unreadable. Standing in for
// std::chrono::steady_clock when telemetry is disabled, this now()/
// time_point subtraction is trivial and side-effect free, so an optimizing
// build (-O1+) discards it entirely instead of paying for a real clock read
// that's only ever handed to a no-op record_*() sink.
struct clock {
    struct time_point {
        friend std::chrono::steady_clock::duration
        operator-(time_point, time_point) noexcept {
            return std::chrono::steady_clock::duration::zero();
        }
        friend bool operator==(time_point, time_point) noexcept { return true; }
        friend bool operator!=(time_point, time_point) noexcept {
            return false;
        }
    };

    static time_point now() noexcept { return time_point{}; }
};

#endif

// One slow-op sample, for the top-10 report. `op` is a static string
// (__FUNCTION__), not owned.
struct SlowOp {
    std::chrono::steady_clock::duration lat;
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

void record_slat(std::chrono::steady_clock::duration d);
void record_rtt(std::chrono::steady_clock::duration d);
void record_clat(std::chrono::steady_clock::duration d);
void record_lat(std::chrono::steady_clock::duration d, unsigned int retries);
void record_op(const SlowOp& op);
void op_started();
void op_finished();
void dump();

#else

inline void record_slat(std::chrono::steady_clock::duration) {
}
inline void record_rtt(std::chrono::steady_clock::duration) {
}
inline void record_clat(std::chrono::steady_clock::duration) {
}
inline void record_lat(std::chrono::steady_clock::duration, unsigned int) {
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
