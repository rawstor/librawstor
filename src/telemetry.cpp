#include "telemetry.hpp"

#ifdef RAWSTOR_TELEMETRY

#include <rawstd/stats.hpp>

#include <atomic>

#include <cstdint>
#include <cstdio>

namespace rawstor {
namespace telemetry {

namespace {

rawstd::Stats g_slat;
rawstd::Stats g_rtt;
rawstd::Stats g_clat;
rawstd::Stats g_lat;
rawstd::Stats g_retries;
rawstd::Stats g_in_flight_stats;

std::atomic<int> g_in_flight{0};

TopN g_top_slow(10);

double usec(std::chrono::steady_clock::duration d) {
    return std::chrono::duration<double, std::micro>(d).count();
}

void print_stat(const char* label, const rawstd::Stats& s) {
    if (s.count() == 0) {
        std::fprintf(stderr, "  %s: N/A\n", label);
        return;
    }
    std::fprintf(
        stderr, "  %s: min=%.2f, max=%.2f, avg=%.2f, stdev=%.2f\n", label,
        s.min(), s.max(), s.mean(), s.stddev()
    );
}

} // namespace

void record_slat(std::chrono::steady_clock::duration d) {
    g_slat.add(usec(d));
}

void record_rtt(std::chrono::steady_clock::duration d) {
    g_rtt.add(usec(d));
}

void record_clat(std::chrono::steady_clock::duration d) {
    g_clat.add(usec(d));
}

void record_lat(std::chrono::steady_clock::duration d, unsigned int retries) {
    g_lat.add(usec(d));
    g_retries.add(static_cast<double>(retries));
}

void record_op(const SlowOp& op) {
    g_top_slow.add(op);
}

void op_started() {
    int n = g_in_flight.fetch_add(1, std::memory_order_relaxed) + 1;
    g_in_flight_stats.add(static_cast<double>(n));
}

void op_finished() {
    int n = g_in_flight.fetch_sub(1, std::memory_order_relaxed) - 1;
    g_in_flight_stats.add(static_cast<double>(n));
}

void dump() {
    if (g_lat.count() == 0) {
        // Telemetry was built in, but no ost:// I/O ever ran -- nothing
        // to report.
        return;
    }

    std::fprintf(stderr, "rawstor: telemetry (ost:// I/O)\n");
    print_stat("slat (usec)", g_slat);
    print_stat("rtt  (usec)", g_rtt);
    print_stat("clat (usec)", g_clat);
    print_stat("lat  (usec)", g_lat);
    print_stat("retries", g_retries);
    print_stat("in-flight requests", g_in_flight_stats);

    std::vector<SlowOp> slow = g_top_slow.sorted();
    if (!slow.empty()) {
        std::fprintf(
            stderr, "  top %zu slowest ost:// requests:\n", slow.size()
        );
        unsigned int i = 1;
        for (const SlowOp& op : slow) {
            std::fprintf(
                stderr,
                "    %2u. %-7s size=%-8zu offset=%-10jd retries=%u "
                "lat=%.0f usec\n",
                i++, op.op, op.size, static_cast<intmax_t>(op.offset),
                op.retries, usec(op.lat)
            );
        }
    }
}

} // namespace telemetry
} // namespace rawstor

#endif // RAWSTOR_TELEMETRY
