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

rawstd::Stats lat_stats;

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

// Bounded top-N by Op::lat, backed by a small binary min-heap so the
// current slowest-of-the-kept-N is found/evicted in O(log N). Shared by
// the ost and blk telemetry domains below -- Op only needs a `lat` field
// and the reversed operator< (bigger lat sorts first) both of their Op
// types already provide.
template <typename Op>
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

} // namespace

void record_lat(TimePoint ns) {
    lat_stats.add(usec(ns));
}

namespace ost {

namespace {

rawstd::Stats slat_stats;
rawstd::Stats rtt_stats;
rawstd::Stats clat_stats;
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

    // Deliberately reversed (bigger lat sorts first): see TopN's own doc
    // comment.
    bool operator<(const Op& other) const noexcept { return lat > other.lat; }
};

TopN<Op> top_slow(10);

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
    if (slat_stats.count() == 0) {
        // Telemetry was built in, but no ost I/O ever ran -- nothing to
        // report for this domain.
        return;
    }

    std::fprintf(stderr, "rawstor: ost telemetry\n");
    print_stat("slat (usec)", slat_stats);
    print_stat("rtt  (usec)", rtt_stats);
    print_stat("clat (usec)", clat_stats);
    print_stat("in-flight requests", in_flight_stats);

    std::vector<Op> slow = top_slow.sorted();
    if (!slow.empty()) {
        std::fprintf(stderr, "  top %zu slowest requests:\n", slow.size());
        unsigned int i = 1;
        for (const Op& op : slow) {
            std::fprintf(
                stderr,
                "    %2u. %-7s size=%-8zu offset=%-10jd "
                "slat=%.0f rtt=%.0f clat=%.0f lat=%.0f usec\n",
                i++, op.op, op.size, static_cast<intmax_t>(op.offset),
                usec(op.slat), usec(op.rtt), usec(op.clat), usec(op.lat)
            );
        }
    }
}

} // namespace ost

namespace blk {

namespace {

rawstd::Stats slat_stats;
rawstd::Stats clat_stats;
rawstd::Stats in_flight_stats;

std::atomic<int> in_flight{0};

// Same role as ost::Op, minus the rtt column -- a blk session's op is a
// direct fd read/write via the io queue, with no round-trip to a remote
// peer to report.
struct Op {
    TimePoint lat;
    TimePoint slat;
    TimePoint clat;
    const char* op;
    size_t size;
    off_t offset;

    bool operator<(const Op& other) const noexcept { return lat > other.lat; }
};

TopN<Op> top_slow(10);

} // namespace

void record_slat(TimePoint ns) {
    slat_stats.add(usec(ns));
}

void record_clat(TimePoint ns) {
    clat_stats.add(usec(ns));
}

void record_op(
    TimePoint lat, TimePoint slat, TimePoint clat, const char* op, size_t size,
    off_t offset
) {
    top_slow.add(Op{lat, slat, clat, op, size, offset});
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
    if (slat_stats.count() == 0) {
        // Telemetry was built in, but no blk I/O ever ran -- nothing to
        // report for this domain.
        return;
    }

    std::fprintf(stderr, "rawstor: blk telemetry\n");
    print_stat("slat (usec)", slat_stats);
    print_stat("clat (usec)", clat_stats);
    print_stat("in-flight requests", in_flight_stats);

    std::vector<Op> slow = top_slow.sorted();
    if (!slow.empty()) {
        std::fprintf(stderr, "  top %zu slowest requests:\n", slow.size());
        unsigned int i = 1;
        for (const Op& op : slow) {
            std::fprintf(
                stderr,
                "    %2u. %-7s size=%-8zu offset=%-10jd "
                "slat=%.0f clat=%.0f lat=%.0f usec\n",
                i++, op.op, op.size, static_cast<intmax_t>(op.offset),
                usec(op.slat), usec(op.clat), usec(op.lat)
            );
        }
    }
}

} // namespace blk

void dump() {
    if (lat_stats.count() == 0) {
        // Telemetry was built in, but no I/O ever ran -- nothing
        // to report.
        return;
    }

    std::fprintf(stderr, "rawstor: telemetry\n");
    print_stat("lat  (usec)", lat_stats);

    ost::dump();
    blk::dump();
}

} // namespace telemetry
} // namespace rawstor

#endif // RAWSTOR_TELEMETRY
