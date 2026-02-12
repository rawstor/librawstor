#include <rawrx/observable.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <list>
#include <string>

namespace {

TEST(ObservableTest, empty) {
    rawrx::Observable<int> o;
    EXPECT_NO_THROW(o.next(42));
}

TEST(ObservableTest, complex) {
    std::string str;
    rawrx::Observable<const std::string&> o;
    o.subscribe([&str](const std::string& s) { str = s; });
    std::string lvalue_string = "hello world";
    o.next(lvalue_string);
    EXPECT_EQ(str, std::string("hello world"));
}

} // namespace
