#include <rawrx/observable.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <list>
#include <string>

namespace {

class Queue {
public:
    using Observable = rawrx::Observable<size_t, int>;

private:
    std::list<Observable> _callbacks;

public:
    Observable& push() {
        _callbacks.emplace_back();
        return _callbacks.back();
    }

    void wait() {
        while (!_callbacks.empty()) {
            _callbacks.front().next(42, 1);
            _callbacks.pop_front();
        }
    }
};

TEST(UseCaseTest, queue) {
    Queue q;
    size_t result = 0;
    int error = 0;
    q.push().subscribe([&result, &error](size_t r, int e) {
        result = r;
        error = e;
    });
    EXPECT_EQ(result, static_cast<size_t>(0));
    EXPECT_EQ(error, 0);
    q.wait();
    EXPECT_EQ(result, static_cast<size_t>(42));
    EXPECT_EQ(error, 1);
}

} // namespace
