#ifndef RAWSTOR_TELEMETRY_HPP
#define RAWSTOR_TELEMETRY_HPP

#include <sys/types.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <vector>

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

// Bounded top-N by SlowOp::lat, backed by a small binary min-heap so the
// current slowest-of-the-kept-N is found/evicted in O(log N). Rawstor/ost
// specific (built around SlowOp) -- not a general-purpose utility, so it
// lives here rather than in librawstd.
class TopN {
private:
    struct ByLat {
        inline bool
        operator()(const SlowOp& a, const SlowOp& b) const noexcept {
            // std::push_heap/pop_heap build a max-heap by default; a
            // reversed comparator turns that into a min-heap, so the
            // *smallest* lat -- the one to evict first when a bigger one
            // shows up -- sits at heap.front().
            return a.lat > b.lat;
        }
    };

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

        if (_heap.size() < _capacity) {
            _heap.push_back(op);
            std::push_heap(_heap.begin(), _heap.end(), ByLat());
        } else if (!_heap.empty() && op.lat > _heap.front().lat) {
            std::pop_heap(_heap.begin(), _heap.end(), ByLat());
            _heap.back() = op;
            std::push_heap(_heap.begin(), _heap.end(), ByLat());
        }
    }

    // Sorted by descending lat, for dump().
    std::vector<SlowOp> sorted() const {
        std::lock_guard<std::mutex> lock(_mutex);
        std::vector<SlowOp> ret(_heap);
        std::sort(ret.begin(), ret.end(), [](const SlowOp& a, const SlowOp& b) {
            return a.lat > b.lat;
        });
        return ret;
    }
};

void record_slat(std::chrono::steady_clock::duration d);
void record_rtt(std::chrono::steady_clock::duration d);
void record_clat(std::chrono::steady_clock::duration d);
void record_lat(std::chrono::steady_clock::duration d, unsigned int retries);
void record_op(const SlowOp& op);
void record_ring_utilization(double fraction);
void record_ring_entries_in_use(unsigned int n);
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
inline void record_ring_utilization(double) {
}
inline void record_ring_entries_in_use(unsigned int) {
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
