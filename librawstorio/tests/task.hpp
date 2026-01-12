#ifndef RAWSTORIO_TESTS_TASK_HPP
#define RAWSTORIO_TESTS_TASK_HPP

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

class SimpleTaskBufferedMultishot final : public rawstor::io::TaskBuffered {
private:
    unsigned int _buffer_size;
    unsigned int _buffer_count;

    void* _buffer;
    size_t* _result;
    int* _error;
    unsigned int* _count;

public:
    SimpleTaskBufferedMultishot(
        unsigned int buffer_size, unsigned int buffer_count, void* buffer,
        size_t* result, int* error, unsigned int* count
    ) :
        _buffer_size(buffer_size),
        _buffer_count(buffer_count),
        _buffer(buffer),
        _result(result),
        _error(error),
        _count(count) {}

    void operator()(size_t result, int error) override {
        if (result > 0) {
            memcpy(_buffer, rawstor::io::TaskBuffered::_buffer, result);
        }
        *_result = result;
        *_error = error;
        ++(*_count);
    }

    unsigned int size() const noexcept override { return _buffer_size; }
    unsigned int count() const noexcept override { return _buffer_count; }
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_TASK_HPP
