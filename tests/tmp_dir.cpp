#include "tmp_dir.hpp"

#include <rawstd/gpp.hpp>

#include <sstream>

#include <unistd.h>

namespace rawstor {
namespace tests {

TmpDir::TmpDir() {
    std::string tmpl =
        (std::filesystem::temp_directory_path() / "rawstor-test-XXXXXX")
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

const std::filesystem::path& TmpDir::path() const noexcept {
    return _path;
}

std::string TmpDir::uri() const {
    std::ostringstream oss;
    oss << "file://" << _path.string();
    return oss.str();
}

} // namespace tests
} // namespace rawstor
