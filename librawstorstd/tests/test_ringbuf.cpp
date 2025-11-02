#include "rawstorstd/ringbuf.hpp"

#include "unittest.h"
#include "unittest.hpp"

#include <memory>
#include <stdexcept>

#include <cerrno>
#include <cstdlib>
#include <cstdio>


namespace {


int test_ringbuf_empty() {
    rawstor::RingBuf<int> buf(3);

    assertThrow(buf.pop(), std::out_of_range);

    assertTrue(buf.empty());
    assertTrue(!buf.full());
    assertTrue(buf.size() == 0);
    assertTrue(buf.capacity() == 3);

    return 0;
}


int test_ringbuf_invalid() {
    rawstor::RingBuf<int> buf(0);

    assertTrue(buf.empty());
    assertTrue(buf.full());

    std::unique_ptr<int> i = std::make_unique<int>(1);

    assertThrow(buf.push(std::move(i)), std::system_error);
    assertThrow(buf.pop(), std::out_of_range);

    return 0;
}


int test_ringbuf_basics() {
    rawstor::RingBuf<int> buf(3);

    assertTrue(buf.size() == 0);
    assertTrue(buf.capacity() == 3);
    assertTrue(buf.empty());
    assertTrue(!buf.full());

    std::unique_ptr<int> i1 = std::make_unique<int>(1);
    buf.push(std::move(i1));
    assertTrue(buf.size() == 1);
    assertTrue(buf.capacity() == 3);
    assertTrue(!buf.empty());
    assertTrue(!buf.full());

    std::unique_ptr<int> i2 = std::make_unique<int>(2);
    buf.push(std::move(i2));
    assertTrue(buf.size() == 2);
    assertTrue(buf.capacity() == 3);
    assertTrue(!buf.empty());
    assertTrue(!buf.full());

    std::unique_ptr<int> i3 = std::make_unique<int>(3);
    buf.push(std::move(i3));
    assertTrue(buf.size() == 3);
    assertTrue(buf.capacity() == 3);
    assertTrue(!buf.empty());
    assertTrue(buf.full());

    std::unique_ptr<int> i4 = std::make_unique<int>(4);
    assertThrow(buf.push(std::move(i4)), std::system_error);
    assertTrue(buf.size() == 3);
    assertTrue(buf.capacity() == 3);
    assertTrue(!buf.empty());
    assertTrue(buf.full());

    std::unique_ptr<int> i;

    assertTrue(buf.tail() == 1);
    i = buf.pop();
    assertTrue(*i == 1);
    assertTrue(buf.size() == 2);
    assertTrue(buf.capacity() == 3);
    assertTrue(!buf.empty());
    assertTrue(!buf.full());

    assertTrue(buf.tail() == 2);
    i = buf.pop();
    assertTrue(*i == 2);
    assertTrue(buf.size() == 1);
    assertTrue(buf.capacity() == 3);
    assertTrue(!buf.empty());
    assertTrue(!buf.full());

    assertTrue(buf.tail() == 3);
    i = buf.pop();
    assertTrue(*i == 3);
    assertTrue(buf.size() == 0);
    assertTrue(buf.capacity() == 3);
    assertTrue(buf.empty());
    assertTrue(!buf.full());

    assertThrow(buf.pop(), std::out_of_range);
    assertTrue(buf.size() == 0);
    assertTrue(buf.capacity() == 3);
    assertTrue(buf.empty());
    assertTrue(!buf.full());

    return 0;
}


int test_ringbuf_overlap() {
    rawstor::RingBuf<int> buf(4);

    assertTrue(buf.size() == 0);

    std::unique_ptr<int> i1 = std::make_unique<int>(1);
    buf.push(std::move(i1));
    assertTrue(buf.size() == 1);

    std::unique_ptr<int> i2 = std::make_unique<int>(2);
    buf.push(std::move(i2));
    assertTrue(buf.size() == 2);

    std::unique_ptr<int> i3 = std::make_unique<int>(3);
    buf.push(std::move(i3));
    assertTrue(buf.size() == 3);

    std::unique_ptr<int> i4 = std::make_unique<int>(4);
    buf.push(std::move(i4));
    assertTrue(buf.size() == 4);

    buf.pop();
    assertTrue(buf.size() == 3);

    std::unique_ptr<int> i5 = std::make_unique<int>(5);
    buf.push(std::move(i5));
    assertTrue(buf.size() == 4);

    buf.pop();
    assertTrue(buf.size() == 3);

    std::unique_ptr<int> i6 = std::make_unique<int>(6);
    buf.push(std::move(i6));
    assertTrue(buf.size() == 4);

    return 0;
}


} // unnamed namespace


int main() {
    int rval = 0;
    rval += test_ringbuf_empty();
    rval += test_ringbuf_invalid();
    rval += test_ringbuf_basics();
    rval += test_ringbuf_overlap();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
