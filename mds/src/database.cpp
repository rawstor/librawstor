#include "database.hpp"

#include "sqlite_database.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <memory>
#include <string>
#include <vector>

#include <cerrno>
#include <cstring>

namespace {

// The SQLite file a `sqlite:///path` connection string names; EINVAL for any
// other form of it.
std::string sqlite_path(const rawstd::URI& uri) {
    if (!uri.authority().empty() || uri.path().filename().empty()) {
        rawstd_error(
            "Invalid SQLite connection string %s: expected "
            "sqlite:///path/to/file\n",
            uri.str().c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return uri.path().str();
}

void check_scheme(const rawstd::URI& uri) {
    if (uri.scheme() == "sqlite") {
        return;
    }
    if (uri.scheme().empty()) {
        rawstd_error(
            "Invalid database connection string %s: no scheme, expected "
            "sqlite:///path/to/file\n",
            uri.str().c_str()
        );
    } else {
        rawstd_error(
            "Unsupported database %s: expected sqlite:///path/to/file\n",
            uri.str().c_str()
        );
    }
    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
}

} // namespace

namespace rawstor {
namespace mdsserver {
namespace db {

void Statement::column_uuid(int pos, RawstdUUID* out) {
    std::vector<unsigned char> blob = column_blob(pos);
    if (blob.size() != sizeof(out->bytes)) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    memcpy(out->bytes, blob.data(), sizeof(out->bytes));
}

void Database::validate(const std::string& uri) {
    rawstd::URI parsed(uri);
    check_scheme(parsed);
    sqlite_path(parsed);
}

std::unique_ptr<Database> Database::open(const std::string& uri) {
    rawstd::URI parsed(uri);
    check_scheme(parsed);
    return std::make_unique<SqliteDatabase>(sqlite_path(parsed));
}

Transaction::Transaction(Database& db) : _db(db), _committed(false) {
    _db.begin();
}

Transaction::~Transaction() {
    if (!_committed) {
        _db.rollback();
    }
}

void Transaction::commit() {
    _db.commit();
    _committed = true;
}

} // namespace db
} // namespace mdsserver
} // namespace rawstor
