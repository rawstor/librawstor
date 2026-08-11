#ifndef RAWSTOR_TELEMETRY_HPP
#define RAWSTOR_TELEMETRY_HPP

#include "config.h"

#include <sys/types.h>

#include <chrono>

#include <cstddef>

namespace rawstor {
namespace telemetry {

// One slow-op sample, for the top-10 report. `op` is a static string
// (__FUNCTION__), not owned.
struct SlowOp {
    std::chrono::steady_clock::duration lat;
    const char* op;
    size_t size;
    off_t offset;
    unsigned int retries;
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
