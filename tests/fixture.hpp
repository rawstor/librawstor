#ifndef RAWSTOR_TESTS_FIXTURE_HPP
#define RAWSTOR_TESTS_FIXTURE_HPP

#include <filesystem>
#include <sstream>
#include <string>

#include <rawstorstd/uri.hpp>

#include <gtest/gtest.h>

namespace rawstor {
namespace tests {

class ObjectTest : public testing::Test {
private:
    std::filesystem::path _path;
    std::string _uris;

protected:
    ObjectTest() :
        _path(std::filesystem::temp_directory_path() / "test_objects") {
        std::filesystem::create_directory(_path);
        std::ostringstream oss;
        oss << "file://" << _path.string();
        _uris = oss.str();
    }
    ~ObjectTest() { std::filesystem::remove_all(_path); }
    const char* uris() const noexcept { return _uris.c_str(); }
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_FIXTURE_HPP
