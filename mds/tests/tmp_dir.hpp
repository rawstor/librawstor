#ifndef RAWSTOR_MDS_TESTS_TMP_DIR_HPP
#define RAWSTOR_MDS_TESTS_TMP_DIR_HPP

#include <filesystem>
#include <string>

namespace rawstor {
namespace mdsserver {
namespace tests {

// A fresh, uniquely-named temporary directory, removed (recursively) when
// the instance is destroyed -- so an ObjectStore under test never shares,
// and can't be polluted by or race against, another test's own SQLite
// file. (Deliberately not reusing ost/tests/tmp_dir.hpp: this binary
// doesn't otherwise link anything from ost/tests/, and duplicating fifteen
// lines beats pulling in a cross-directory source dependency for them.)
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

    // A fresh SQLite path under this directory -- ObjectStore's own
    // constructor creates the file itself (SQLITE_OPEN_CREATE), so this
    // just names where.
    std::string db_path() const;
};

} // namespace tests
} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_TESTS_TMP_DIR_HPP
