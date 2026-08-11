#include "telemetry.hpp"

#ifdef RAWSTOR_TELEMETRY

#include <rawstd/stats.hpp>

#include <algorithm>
#include <atomic>
#include <mutex>
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
rawstd::Stats retries_stats;
rawstd::Stats in_flight_stats;

std::atomic<int> in_flight{0};

// Bounded top-N by SlowOp::lat, backed by a small binary min-heap so the
// current slowest-of-the-kept-N is found/evicted in O(log N). Only ever
// used here, as top_slow below -- not a general-purpose utility.
class TopN {
private:
    mutable std::mutex _mutex;
    size_t _capacity;
    std::vector<SlowOp> _heap;

public:
    explicit TopN(size_t capacity) : _capacity(capacity) {}

    TopN(const TopN&) = delete;
    TopN(TopN&&) = delete;
    TopN& operator=(const TopN&) = delete;
    TopN& operator=(TopN&&) = delete;

    void add(const SlowOp& op) {
        std::lock_guard<std::mutex> lock(_mutex);

        // std::push_heap/pop_heap build a max-heap by SlowOp::operator<,
        // which is reversed -- so the *smallest* lat, the one to evict
        // first when a bigger one shows up, sits at heap.front().
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
    std::vector<SlowOp> sorted() const {
        std::lock_guard<std::mutex> lock(_mutex);
        std::vector<SlowOp> ret(_heap);
        std::sort(ret.begin(), ret.end());
        return ret;
    }
};

TopN top_slow(10);

double usec(TimePoint ns) {
    return static_cast<double>(ns) / 1000.0;
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

void record_slat(TimePoint ns) {
    slat_stats.add(usec(ns));
}

void record_rtt(TimePoint ns) {
    rtt_stats.add(usec(ns));
}

void record_clat(TimePoint ns) {
    clat_stats.add(usec(ns));
}

void record_lat(TimePoint ns, unsigned int retries) {
    lat_stats.add(usec(ns));
    retries_stats.add(static_cast<double>(retries));
}

void record_op(const SlowOp& op) {
    top_slow.add(op);
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
    print_stat("retries", retries_stats);
    print_stat("in-flight requests", in_flight_stats);

    std::vector<SlowOp> slow = top_slow.sorted();
    if (!slow.empty()) {
        std::fprintf(stderr, "  top %zu slowest requests:\n", slow.size());
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
