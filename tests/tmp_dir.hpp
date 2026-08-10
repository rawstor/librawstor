#ifndef RAWSTOR_TESTS_TMP_DIR_HPP
#define RAWSTOR_TESTS_TMP_DIR_HPP

#include <filesystem>
#include <string>

namespace rawstor {
namespace tests {

// A fresh, uniquely-named temporary directory, removed (recursively) when
// the instance is destroyed. Each test gets its own, so tests using the
// `file://` backend never share -- and can't be polluted by, or race
// against -- another test's on-disk location.
class TmpDir {
private:
    std::filesystem::path _path;

public:
    TmpDir();
    ~TmpDir();

    TmpDir(const TmpDir&) = delete;
    TmpDir& operator=(const TmpDir&) = delete;
    TmpDir(TmpDir&&) = delete;
    TmpDir& operator=(TmpDir&&) = delete;

    const std::filesystem::path& path() const noexcept;

    std::string uri() const;
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_TMP_DIR_HPP
