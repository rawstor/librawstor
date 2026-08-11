#include <rawstd/stats.hpp>

#include <cmath>

namespace rawstd {

Stats::Stats() : _count(0), _mean(0.0), _m2(0.0), _min(0.0), _max(0.0) {
}

void Stats::add(double value) {
    std::lock_guard<std::mutex> lock(_mutex);

    if (_count == 0) {
        _min = value;
        _max = value;
    } else {
        if (value < _min) {
            _min = value;
        }
        if (value > _max) {
            _max = value;
        }
    }

    ++_count;
    double delta = value - _mean;
    _mean += delta / static_cast<double>(_count);
    double delta2 = value - _mean;
    _m2 += delta * delta2;
}

unsigned long long Stats::count() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _count;
}

double Stats::min() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _min;
}

double Stats::max() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _max;
}

double Stats::mean() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _mean;
}

double Stats::stddev() const {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_count == 0) {
        return 0.0;
    }
    return std::sqrt(_m2 / static_cast<double>(_count));
}

} // namespace rawstd
