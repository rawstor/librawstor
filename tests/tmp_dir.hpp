#ifndef RAWSTOR_TESTS_TMP_DIR_HPP
#define RAWSTOR_TESTS_TMP_DIR_HPP

#include <rawstd/gpp.hpp>

#include <filesystem>
#include <sstream>
#include <string>

#include <unistd.h>

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
    TmpDir() {
        std::string tmpl =
            (std::filesystem::temp_directory_path() / "rawstor-test-XXXXXX")
                .string();
        if (mkdtemp(tmpl.data()) == nullptr) {
            RAWSTD_THROW_ERRNO();
        }
        _path = tmpl;
    }

    TmpDir(const TmpDir&) = delete;
    TmpDir& operator=(const TmpDir&) = delete;

    ~TmpDir() {
        std::error_code ec;
        std::filesystem::remove_all(_path, ec);
    }

    const std::filesystem::path& path() const {
        return _path;
    }

    std::string uri() const {
        std::ostringstream oss;
        oss << "file://" << _path.string();
        return oss.str();
    }
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_TMP_DIR_HPP
