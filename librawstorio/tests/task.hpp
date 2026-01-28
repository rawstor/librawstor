#ifndef RAWSTORIO_TESTS_TASK_HPP
#define RAWSTORIO_TESTS_TASK_HPP

#include <rawstorstd/iovec.h>

#include <rawstorio/task.hpp>

#include <vector>

namespace rawstor {
namespace io {
namespace tests {

class SimpleTask final : public rawstor::io::Task {
private:
    size_t* _result;
    int* _error;

public:
    SimpleTask(size_t* result, int* error) : _result(result), _error(error) {}

    void operator()(size_t result, int error) override {
        *_result = result;
        *_error = error;
    }
};

class SimpleTaskMultishot final : public rawstor::io::Task {
private:
    size_t* _result;
    int* _error;
    unsigned int* _count;

public:
    SimpleTaskMultishot(size_t* result, int* error, unsigned int* count) :
        _result(result),
        _error(error),
        _count(count) {}

    void operator()(size_t result, int error) override {
        *_result = result;
        *_error = error;
        ++(*_count);
    }
};

class SimpleTaskScalar final : public rawstor::io::TaskScalar {
private:
    void* _buf;
    size_t _size;

    size_t* _result;
    int* _error;

public:
    SimpleTaskScalar(void* buf, size_t size, size_t* result, int* error) :
        rawstor::io::TaskScalar(),
        _buf(buf),
        _size(size),
        _result(result),
        _error(error) {}

    void operator()(size_t result, int error) override {
        *_result = result;
        *_error = error;
    }

    void* buf() noexcept override { return _buf; }
    size_t size() const noexcept override { return _size; }
};

class SimpleTaskVectorExternalItem {
private:
    std::vector<char> _data;
    const size_t _result;
    const int _error;

public:
    SimpleTaskVectorExternalItem(
        iovec* iov, unsigned int niov, size_t result, int error
    ) :
        _data(result),
        _result(result),
        _error(error) {
        if (result > 0) {
            rawstor_iovec_to_buf(iov, niov, 0, _data.data(), result);
        }
    }

    const char* data() const noexcept { return _data.data(); }
    size_t result() const noexcept { return _result; }
    int error() const noexcept { return _error; }
};

class SimpleTaskVectorExternal final : public rawstor::io::TaskVectorExternal {
private:
    size_t _size;
    std::vector<SimpleTaskVectorExternalItem>* _items;

public:
    SimpleTaskVectorExternal(
        size_t size, std::vector<SimpleTaskVectorExternalItem>* items
    ) :
        _size(size),
        _items(items) {}

    void operator()(size_t result, int error) override {
        if (result > 0) {
            std::vector<char> s(result + 1);
            rawstor_iovec_to_buf(iov(), niov(), 0, s.data(), s.size());
        }
        _items->emplace_back(iov(), niov(), result, error);
    }

    size_t size() const noexcept override { return _size; }
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_TASK_HPP
