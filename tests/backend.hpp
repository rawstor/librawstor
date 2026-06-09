#ifndef RAWSTOR_TESTS_BACKEND_HPP
#define RAWSTOR_TESTS_BACKEND_HPP

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace rawstor {
namespace tests {

class Backend {
public:
    Backend() = default;
    Backend(const Backend&) = delete;
    Backend(Backend&&) = delete;
    virtual ~Backend() = default;

    Backend& operator=(const Backend&) = delete;
    Backend& operator=(Backend&&) = delete;

    virtual void accept() = 0;

    virtual void read(void* buf, size_t size) = 0;

    virtual void write(const void* buf, size_t size) = 0;

    virtual void wait() = 0;

    virtual void close() = 0;

    virtual std::string uris() const noexcept = 0;

    virtual std::string protocol() const noexcept = 0;
};

extern const std::vector<std::shared_ptr<Backend>> backends;

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_BACKEND_HPP
