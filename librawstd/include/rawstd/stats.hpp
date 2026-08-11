#ifndef RAWSTD_STATS_HPP
#define RAWSTD_STATS_HPP

#include <mutex>

namespace rawstd {

// Running min/max/mean/stddev over an unbounded stream of samples
// (Welford's online algorithm) -- samples themselves are not retained.
// Thread-safe: add() and the accessors may be called concurrently.
class Stats {
private:
    mutable std::mutex _mutex;
    unsigned long long _count;
    double _mean;
    double _m2;
    double _min;
    double _max;

public:
    Stats();

    Stats(const Stats&) = delete;
    Stats(Stats&&) = delete;
    Stats& operator=(const Stats&) = delete;
    Stats& operator=(Stats&&) = delete;

    void add(double value);

    unsigned long long count() const;

    // min()/max()/mean()/stddev() are meaningless on an empty accumulator
    // (count() == 0) -- check count() first.
    double min() const;
    double max() const;
    double mean() const;
    double stddev() const;
};

} // namespace rawstd

#endif // RAWSTD_STATS_HPP
