#include "tmp_dir.hpp"

#include <rawstd/gpp.hpp>

#include <unistd.h>

namespace rawstor {
namespace mdsserver {
namespace tests {

TmpDir::TmpDir() {
    std::string tmpl =
        (std::filesystem::temp_directory_path() / "rawstor-mds-test-XXXXXX")
            .string();
    if (mkdtemp(tmpl.data()) == nullptr) {
        RAWSTD_THROW_ERRNO();
    }
    _path = tmpl;
}

TmpDir::~TmpDir() {
    std::error_code ec;
    std::filesystem::remove_all(_path, ec);
}

std::string TmpDir::db_path() const {
    return (_path / "mds.db").string();
}

} // namespace tests
} // namespace mdsserver
} // namespace rawstor
