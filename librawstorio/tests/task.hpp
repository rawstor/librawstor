#ifndef RAWSTORIO_TESTS_TASK_HPP
#define RAWSTORIO_TESTS_TASK_HPP

#include <rawstorstd/iovec.h>

#include <rawstorio/task.hpp>

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

class SimpleTaskVectorExternal final : public rawstor::io::TaskVectorExternal {
private:
    size_t _size;
    void* _buffer;
    size_t* _result;
    int* _error;
    unsigned int* _count;

public:
    SimpleTaskVectorExternal(
        size_t size, void* buffer, size_t* result, int* error,
        unsigned int* count
    ) :
        _size(size),
        _buffer(buffer),
        _result(result),
        _error(error),
        _count(count) {}

    void operator()(size_t result, int error) override {
        if (result > 0) {
            rawstor_iovec_to_buf(
                iov(), niov(), 0, _buffer, rawstor_iovec_size(iov(), niov())
            );
        }
        *_result = result;
        *_error = error;
        ++(*_count);
    }

    size_t size() const noexcept override { return _size; }
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_TASK_HPP
