#include <rawrx/observable.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <list>
#include <string>

namespace {

TEST(PipeTest, map) {
    int result = 0;
    rawrx::Observable<int> o;
    o.pipe(rawrx::Observable<int>::map([](int& r) {
         r *= 2;
     })).subscribe([&result](int r) { result = r; });
    o.next(42);
    EXPECT_EQ(result, 84);
}

TEST(PipeTest, filter) {
    std::vector<int> output;
    rawrx::Observable<int> o;
    o.pipe(rawrx::Observable<int>::filter([](int result) -> bool {
         return result % 2 != 0;
     })).subscribe([&output](int result) { output.push_back(result); });
    o.next(1);
    o.next(2);
    o.next(3);
    EXPECT_EQ(output, (std::vector<int>{1, 3}));
}

} // namespace
