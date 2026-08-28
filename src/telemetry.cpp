#include "telemetry.hpp"

#ifdef RAWSTOR_TELEMETRY

#include <rawstd/stats.hpp>
#include <rawstd/units.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include <cstdint>
#include <cstdio>

namespace rawstor {
namespace telemetry {

namespace {

rawstd::Stats slat_stats;
rawstd::Stats rtt_stats;
rawstd::Stats clat_stats;
rawstd::Stats lat_stats;
rawstd::Stats in_flight_stats;

std::atomic<int> in_flight{0};

// One slow-op sample, for the top-10 report. `op` is a static string
// (a string literal in the caller), not owned. Internal to this file:
// record_op() takes its fields individually, so nothing outside needs
// the type itself.
struct Op {
    TimePoint lat;
    TimePoint slat;
    TimePoint rtt;
    TimePoint clat;
    const char* op;
    size_t size;
    off_t offset;

    // Deliberately reversed (bigger lat sorts first): lets TopN drive
    // std::push_heap/pop_heap/sort with the default comparator, no
    // separate predicate needed.
    bool operator<(const Op& other) const noexcept { return lat > other.lat; }
};

// Bounded top-N by Op::lat, backed by a small binary min-heap so the
// current slowest-of-the-kept-N is found/evicted in O(log N).
class TopN {
private:
    mutable std::mutex _mutex;
    size_t _capacity;
    std::vector<Op> _heap;

public:
    explicit TopN(size_t capacity) : _capacity(capacity) {}

    TopN(const TopN&) = delete;
    TopN(TopN&&) = delete;
    TopN& operator=(const TopN&) = delete;
    TopN& operator=(TopN&&) = delete;

    void add(const Op& op) {
        std::lock_guard<std::mutex> lock(_mutex);

        // std::push_heap/pop_heap build a max-heap by Op::operator<, which
        // is reversed -- so the *smallest* lat, the one to evict first
        // when a bigger one shows up, sits at heap.front().
        if (_heap.size() < _capacity) {
            _heap.push_back(op);
            std::push_heap(_heap.begin(), _heap.end());
        } else if (!_heap.empty() && op < _heap.front()) {
            std::pop_heap(_heap.begin(), _heap.end());
            _heap.back() = op;
            std::push_heap(_heap.begin(), _heap.end());
        }
    }

    // Sorted by descending lat, for dump().
    std::vector<Op> sorted() const {
        std::lock_guard<std::mutex> lock(_mutex);
        std::vector<Op> ret(_heap);
        std::sort(ret.begin(), ret.end());
        return ret;
    }
};

TopN top_slow(10);

double usec(TimePoint ns) {
    return static_cast<double>(ns) / 1000.0;
}

// "'"-grouped rendering of a non-negative value (see rawstd_uint64_grouped()
// -- every value dump() prints is a latency, size, offset, or count, never
// negative), rounded to `decimals` fractional digits.
std::string grouped(double value, int decimals) {
    uint64_t scale = 1;
    for (int i = 0; i < decimals; ++i) {
        scale *= 10;
    }
    uint64_t scaled =
        static_cast<uint64_t>(value * static_cast<double>(scale) + 0.5);

    char int_buf[32];
    rawstd_uint64_grouped(scaled / scale, int_buf, sizeof(int_buf));
    if (decimals == 0) {
        return int_buf;
    }

    char out[48];
    std::snprintf(
        out, sizeof(out), "%s.%0*llu", int_buf, decimals,
        (unsigned long long)(scaled % scale)
    );
    return out;
}

std::string grouped(uint64_t value) {
    char buf[32];
    rawstd_uint64_grouped(value, buf, sizeof(buf));
    return buf;
}

void print_stat(const char* label, const rawstd::Stats& s) {
    if (s.count() == 0) {
        std::fprintf(stderr, "  %s: N/A\n", label);
        return;
    }
    std::fprintf(
        stderr, "  %s: min=%s, max=%s, avg=%s, stdev=%s\n", label,
        grouped(s.min(), 2).c_str(), grouped(s.max(), 2).c_str(),
        grouped(s.mean(), 2).c_str(), grouped(s.stddev(), 2).c_str()
    );
}

} // namespace

void record_slat(TimePoint ns) {
    slat_stats.add(usec(ns));
}

void record_rtt(TimePoint ns) {
    rtt_stats.add(usec(ns));
}

void record_clat(TimePoint ns) {
    clat_stats.add(usec(ns));
}

void record_lat(TimePoint ns) {
    lat_stats.add(usec(ns));
}

void record_op(
    TimePoint lat, TimePoint slat, TimePoint rtt, TimePoint clat,
    const char* op, size_t size, off_t offset
) {
    top_slow.add(Op{lat, slat, rtt, clat, op, size, offset});
}

void op_started() {
    int n = in_flight.fetch_add(1, std::memory_order_relaxed) + 1;
    in_flight_stats.add(static_cast<double>(n));
}

void op_finished() {
    int n = in_flight.fetch_sub(1, std::memory_order_relaxed) - 1;
    in_flight_stats.add(static_cast<double>(n));
}

void dump() {
    if (lat_stats.count() == 0) {
        // Telemetry was built in, but no I/O ever ran -- nothing
        // to report.
        return;
    }

    std::fprintf(stderr, "rawstor: telemetry\n");
    print_stat("slat (usec)", slat_stats);
    print_stat("rtt  (usec)", rtt_stats);
    print_stat("clat (usec)", clat_stats);
    print_stat("lat  (usec)", lat_stats);
    print_stat("in-flight requests", in_flight_stats);

    std::vector<Op> slow = top_slow.sorted();
    if (!slow.empty()) {
        std::fprintf(stderr, "  top %zu slowest requests:\n", slow.size());
        unsigned int i = 1;
        for (const Op& op : slow) {
            std::fprintf(
                stderr,
                "    %2u. %-7s size=%-10s offset=%-12s "
                "slat=%s rtt=%s clat=%s lat=%s usec\n",
                i++, op.op, grouped(static_cast<uint64_t>(op.size)).c_str(),
                grouped(static_cast<uint64_t>(op.offset)).c_str(),
                grouped(usec(op.slat), 0).c_str(),
                grouped(usec(op.rtt), 0).c_str(),
                grouped(usec(op.clat), 0).c_str(),
                grouped(usec(op.lat), 0).c_str()
            );
        }
    }
}

} // namespace telemetry
} // namespace rawstor

#endif // RAWSTOR_TELEMETRY
