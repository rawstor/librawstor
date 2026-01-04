#ifndef RAWSTORIO_TESTS_TASK_HPP
#define RAWSTORIO_TESTS_TASK_HPP

#include <rawstorio/task.hpp>

namespace rawstor {
namespace io {
namespace tests {

class SimpleTask final : public rawstor::io::TaskScalar {
private:
    void* _buf;
    size_t _size;

    size_t& _result;
    int& _error;

public:
    SimpleTask(int fd, void* buf, size_t size, size_t& result, int& error) :
        rawstor::io::TaskScalar(fd),
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

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_TASK_HPP
