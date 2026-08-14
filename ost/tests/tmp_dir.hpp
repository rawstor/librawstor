#ifndef RAWSTOR_OSTBACKEND_TESTS_TMP_DIR_HPP
#define RAWSTOR_OSTBACKEND_TESTS_TMP_DIR_HPP

#include <filesystem>
#include <string>

namespace rawstor {
namespace ostbackend {
namespace tests {

// A fresh, uniquely-named temporary directory, removed (recursively) when
// the instance is destroyed -- so a file:// Server under test never
// shares, and can't be polluted by or race against, another test's
// on-disk location. (Deliberately not reusing tests/tmp_dir.hpp: this
// binary doesn't otherwise link anything from tests/, and duplicating
// fifteen lines beats pulling in a cross-directory source dependency for
// them.)
class TmpDir final {
private:
    std::filesystem::path _path;

public:
    TmpDir();
    TmpDir(const TmpDir&) = delete;
    TmpDir(TmpDir&&) = delete;
    ~TmpDir();

    TmpDir& operator=(const TmpDir&) = delete;
    TmpDir& operator=(TmpDir&&) = delete;

    std::string uri() const;
};

} // namespace tests
} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_TESTS_TMP_DIR_HPP
