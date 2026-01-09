#ifndef RAWSTORIO_TESTS_TASK_HPP
#define RAWSTORIO_TESTS_TASK_HPP

#include <rawstorio/task.hpp>

namespace rawstor {
namespace io {
namespace tests {

class SimpleScalarTask final : public rawstor::io::TaskScalar {
private:
    void* _buf;
    size_t _size;

    size_t& _result;
    int& _error;

public:
    SimpleScalarTask(void* buf, size_t size, size_t& result, int& error) :
        rawstor::io::TaskScalar(),
        _buf(buf),
        _size(size),
        _result(result),
        _error(error) {}

    void operator()(size_t result, int error) override {
        _result = result;
        _error = error;
    }

    void* buf() noexcept override { return _buf; }
    size_t size() const noexcept override { return _size; }
};

class SimplePollTask final : public rawstor::io::Task {
private:
    size_t& _result;
    int& _error;

public:
    SimplePollTask(size_t& result, int& error) :
        _result(result),
        _error(error) {}

    void operator()(size_t result, int error) override {
        _result = result;
        _error = error;
    }
};

class SimplePollMultishotTask final : public rawstor::io::Task {
private:
    size_t& _result;
    int& _error;
    unsigned int& _count;

public:
    SimplePollMultishotTask(size_t& result, int& error, unsigned int& count) :
        _result(result),
        _error(error),
        _count(count) {}

    void operator()(size_t result, int error) override {
        _result = result;
        _error = error;
        ++_count;
    }
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_TASK_HPP
